import logging
from os import kill  # pylint: disable=[no-name-in-module]
from pathlib import Path
from typing import Any, Dict, Iterable, NoReturn, Optional, Union, cast
from xmlrpc.client import Fault, ServerProxy

import supervisor.xmlrpc  # type: ignore[import]

from knot_resolver_manager.compat.asyncio import async_in_a_thread
from knot_resolver_manager.constants import supervisord_config_file, supervisord_pid_file, supervisord_sock_file
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import CancelStartupExecInsteadException, SubprocessControllerException
from knot_resolver_manager.kresd_controller.interface import (
    KresID,
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.kresd_controller.supervisord.config_file import SupervisordKresID, write_config_file
from knot_resolver_manager.utils import which
from knot_resolver_manager.utils.async_utils import call, readfile

logger = logging.getLogger(__name__)


async def _start_supervisord(config: KresConfig) -> None:
    logger.debug("Writing supervisord config")
    await write_config_file(config)
    logger.debug("Starting supervisord")
    res = await call(["supervisord", "--configuration", str(supervisord_config_file(config).absolute())])
    if res != 0:
        raise SubprocessControllerException(f"Supervisord exited with exit code {res}")


async def _exec_supervisord(config: KresConfig) -> NoReturn:
    logger.debug("Writing supervisord config")
    await write_config_file(config)
    logger.debug("Execing supervisord")
    raise CancelStartupExecInsteadException(
        [
            str(which.which("supervisord")),
            "supervisord",
            "--configuration",
            str(supervisord_config_file(config).absolute()),
        ]
    )


async def _reload_supervisord(config: KresConfig) -> None:
    await write_config_file(config)
    try:
        supervisord = _create_supervisord_proxy(config)
        supervisord.reloadConfig()
    except Fault as e:
        raise SubprocessControllerException("supervisord reload failed") from e


@async_in_a_thread
def _stop_supervisord(config: KresConfig) -> None:
    supervisord = _create_supervisord_proxy(config)
    # pid = supervisord.getPID()
    try:
        # we might be trying to shut down supervisord at a moment, when it's waiting
        # for us to stop. Therefore, this shutdown request for supervisord might
        # die and it's not a problem.
        supervisord.shutdown()
    except Fault as e:
        if e.faultCode == 6 and e.faultString == "SHUTDOWN_STATE":
            # supervisord is already stopping, so it's fine
            pass
        else:
            # something wrong happened, let's be loud about it
            raise

    # We could remove the configuration, but there is actually no specific need to do so.
    # If we leave it behind, someone might find it and use it to start us from scratch again,
    # which is perfectly fine.
    # supervisord_config_file(config).unlink()


async def _is_supervisord_available() -> bool:
    # yes, it is! The code in this file wouldn't be running without it due to imports :)

    # so let's just check that we can find supervisord and supervisorctl binaries
    try:
        which.which("supervisord")
        which.which("supervisorctl")
    except RuntimeError:
        logger.error("Failed to find supervisord or supervisorctl executables in $PATH")
        return False

    return True


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


def _create_proxy(config: KresConfig) -> ServerProxy:
    return ServerProxy(
        "http://127.0.0.1",
        transport=supervisor.xmlrpc.SupervisorTransport(
            None, None, serverurl="unix://" + str(supervisord_sock_file(config))
        ),
    )


def _create_supervisord_proxy(config: KresConfig) -> Any:
    proxy = _create_proxy(config)
    return getattr(proxy, "supervisor")


def _create_fast_proxy(config: KresConfig) -> Any:
    proxy = _create_proxy(config)
    return getattr(proxy, "fast")


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
            "EXITED": SubprocessStatus.EXITED,
            "FATAL": SubprocessStatus.FAILED,
            "UNKNOWN": SubprocessStatus.UNKNOWN,
        }

        if proc["statename"] in conversion_tbl:
            status = conversion_tbl[proc["statename"]]
        else:
            logger.warning(f"Unknown supervisord process state {proc['statename']}")
            status = SubprocessStatus.UNKNOWN
        return status

    # there will be a manager process as well, but we don't want to report anything on ourselves
    processes = [pr for pr in processes if pr["name"] != "manager"]

    # convert all the names
    return {
        SupervisordKresID.from_string(f"{pr['group']}:{pr['name']}"): convert(pr)
        for pr in processes
        if pr["statename"] != "STOPPED"
    }


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

    @property
    def name(self):
        return str(self.id)

    @async_in_a_thread
    def _start(self) -> None:
        # +1 for canary process (same as in config_file.py)
        assert int(self.id) <= int(self._config.max_workers) + 1, "trying to spawn more than allowed limit of workers"
        try:
            supervisord = _create_fast_proxy(self._config)
            supervisord.startProcess(self.name)
        except Fault as e:
            raise SubprocessControllerException(f"failed to start '{self.id}'") from e

    @async_in_a_thread
    def _stop(self) -> None:
        supervisord = _create_supervisord_proxy(self._config)
        supervisord.stopProcess(self.name)

    @async_in_a_thread
    def _restart(self) -> None:
        supervisord = _create_supervisord_proxy(self._config)
        supervisord.stopProcess(self.name)
        fast = _create_fast_proxy(self._config)
        fast.startProcess(self.name)

    def get_used_config(self) -> KresConfig:
        return self._config


class SupervisordSubprocessController(SubprocessController):
    def __init__(self):  # pylint: disable=super-init-not-called
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
            logger.info(
                "We want supervisord to restart us when needed, we will therefore exec() it and let it start us again."
            )
            await _exec_supervisord(config)
        else:
            logger.info("Supervisord is already running, we will just update its config...")
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
