import logging
from os import kill
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Union, cast
from xmlrpc.client import ServerProxy

import supervisor.xmlrpc  # type: ignore[import]

from knot_resolver_manager.compat.asyncio import async_in_a_thread
from knot_resolver_manager.constants import supervisord_config_file, supervisord_pid_file, supervisord_sock_file
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kresd_controller.interface import (
    KresID,
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.kresd_controller.supervisord.config_file import SupervisordKresID, write_config_file
from knot_resolver_manager.utils.async_utils import call, readfile

logger = logging.getLogger(__name__)


async def _start_supervisord(config: KresConfig) -> None:
    await write_config_file(config)
    res = await call(f'supervisord --configuration="{supervisord_config_file(config).absolute()}"', shell=True)
    if res != 0:
        raise SubprocessControllerException(f"Supervisord exited with exit code {res}")


async def _reload_supervisord(config: KresConfig) -> None:
    await write_config_file(config)
    res = await call(f'supervisorctl --configuration="{supervisord_config_file(config).absolute()}" update', shell=True)
    if res != 0:
        raise SubprocessControllerException(f"Supervisord reload failed with exit code {res}")


@async_in_a_thread
def _stop_supervisord(config: KresConfig) -> None:
    supervisord = _create_supervisord_proxy(config)
    supervisord.shutdown()
    supervisord_config_file(config).unlink()


async def _is_supervisord_available() -> bool:
    i = await call("supervisorctl -h > /dev/null", shell=True, discard_output=True)
    i += await call("supervisord -h > /dev/null", shell=True, discard_output=True)
    return i == 0


async def _get_supervisord_pid(config: KresConfig) -> Optional[int]:
    if not Path(supervisord_pid_file(config)).exists():
        return None

    return int(await readfile(supervisord_pid_file(config)))


def _is_process_runinng(pid: int) -> bool:
    try:
        # kill with signal 0 is a safe way to test that a process exists
        kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


async def _is_supervisord_running(config: KresConfig) -> bool:
    pid = await _get_supervisord_pid(config)
    if pid is None:
        return False
    elif not _is_process_runinng(pid):
        supervisord_pid_file(config).unlink()
        return False
    else:
        return True


def _create_supervisord_proxy(config: KresConfig) -> Any:
    proxy = ServerProxy(
        "http://127.0.0.1",
        transport=supervisor.xmlrpc.SupervisorTransport(
            None, None, serverurl="unix://" + str(supervisord_sock_file(config))
        ),
    )
    return getattr(proxy, "supervisor")


def _list_running_subprocesses(config: KresConfig) -> Dict[SupervisordKresID, SubprocessStatus]:
    supervisord = _create_supervisord_proxy(config)
    processes: Any = supervisord.getAllProcessInfo()

    def convert(proc: Any) -> SubprocessStatus:
        conversion_tbl = {
            # "STOPPED": None,  # filtered out elsewhere
            "STARTING": SubprocessStatus.RUNNING,
            "RUNNING": SubprocessStatus.RUNNING,
            "BACKOFF": SubprocessStatus.RUNNING,
            "STOPPING": SubprocessStatus.RUNNING,
            "EXITED": SubprocessStatus.FAILED,
            "FATAL": SubprocessStatus.FAILED,
            "UNKNOWN": SubprocessStatus.UNKNOWN,
        }

        if proc["statename"] in conversion_tbl:
            status = conversion_tbl[proc["statename"]]
        else:
            logger.warning(f"Unknown supervisord process state {proc['statename']}")
            status = SubprocessStatus.UNKNOWN
        return status

    return {SupervisordKresID.from_string(pr["name"]): convert(pr) for pr in processes if pr["statename"] != "STOPPED"}


class SupervisordSubprocess(Subprocess):
    def __init__(
        self,
        config: KresConfig,
        controller: "SupervisordSubprocessController",
        base_id: Union[SubprocessType, SupervisordKresID],
    ):
        if isinstance(base_id, SubprocessType):
            super().__init__(config, SupervisordKresID.alloc(base_id))
        else:
            super().__init__(config, base_id)
        self._controller: "SupervisordSubprocessController" = controller

    @async_in_a_thread
    def _start(self) -> None:
        supervisord = _create_supervisord_proxy(self._config)
        supervisord.startProcess(str(self.id))

    @async_in_a_thread
    def _stop(self) -> None:
        supervisord = _create_supervisord_proxy(self._config)
        supervisord.stopProcess(str(self.id))

    @async_in_a_thread
    def _restart(self) -> None:
        supervisord = _create_supervisord_proxy(self._config)
        supervisord.stopProcess(str(self.id))
        supervisord.startProcess(str(self.id))

    def get_used_config(self) -> KresConfig:
        return self._config


class SupervisordSubprocessController(SubprocessController):
    def __init__(self):
        self._controller_config: Optional[KresConfig] = None

    def __str__(self):
        return "supervisord"

    async def is_controller_available(self, config: KresConfig) -> bool:
        res = await _is_supervisord_available()
        if not res:
            logger.info("Failed to find usable supervisord.")

        logger.debug("Detection - supervisord controller is available for use")
        return res

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        assert self._controller_config is not None

        if await _is_supervisord_running(self._controller_config):
            states = _list_running_subprocesses(self._controller_config)
            return [
                SupervisordSubprocess(self._controller_config, self, id_)
                for id_ in states
                if states[id_] == SubprocessStatus.RUNNING
            ]
        else:
            return []

    async def initialize_controller(self, config: KresConfig) -> None:
        self._controller_config = config

        if not await _is_supervisord_running(config):
            await _start_supervisord(config)
        else:
            await _reload_supervisord(config)

    async def shutdown_controller(self) -> None:
        assert self._controller_config is not None
        await _stop_supervisord(self._controller_config)

    async def create_subprocess(self, subprocess_config: KresConfig, subprocess_type: SubprocessType) -> Subprocess:
        return SupervisordSubprocess(subprocess_config, self, subprocess_type)

    @async_in_a_thread
    def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        assert self._controller_config is not None
        return cast(Dict[KresID, SubprocessStatus], _list_running_subprocesses(self._controller_config))
