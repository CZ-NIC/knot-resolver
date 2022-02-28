import configparser
import logging
import os
import signal
from os import kill
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Union
from xmlrpc.client import ServerProxy

import supervisor.xmlrpc  # type: ignore[import]
from jinja2 import Template

from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import (
    kres_gc_executable,
    kresd_cache_dir,
    kresd_config_file,
    kresd_executable,
    supervisord_config_file,
    supervisord_config_file_tmp,
    supervisord_log_file,
    supervisord_pid_file,
    supervisord_sock_file,
    supervisord_subprocess_log_dir,
)
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kresd_controller.interface import (
    KresID,
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.utils.async_utils import (
    call,
    read_resource,
    readfile,
    wait_for_process_termination,
    writefile,
)

logger = logging.getLogger(__name__)


class SupervisordKresID(KresID):
    @staticmethod
    def from_string(val: str) -> "SupervisordKresID":
        if val == "gc":
            return SupervisordKresID.new(SubprocessType.GC, -1)
        else:
            val = val.replace("kresd", "")
            return SupervisordKresID.new(SubprocessType.KRESD, int(val))

    def __str__(self) -> str:
        if self.subprocess_type is SubprocessType.GC:
            return "gc"
        elif self.subprocess_type is SubprocessType.KRESD:
            return f"kresd{self._id}"
        else:
            raise RuntimeError(f"Unexpected subprocess type {self.subprocess_type}")


@dataclass
class _Instance:
    """
    Data structure holding data for supervisord config template
    """

    type: str
    logfile: str
    id: str
    workdir: str
    command: str
    environment: str


def _get_command_based_on_type(config: KresConfig, i: "SupervisordSubprocess") -> str:
    if i.type is SubprocessType.KRESD:
        return f"{kresd_executable()} -c {kresd_config_file(config, i.id)} -n"
    elif i.type is SubprocessType.GC:
        return f"{kres_gc_executable()} -c {kresd_cache_dir(config)} -d 1000"
    else:
        raise NotImplementedError("This subprocess type is not supported")


async def _write_config_file(config: KresConfig, instances: Set["SupervisordSubprocess"]) -> None:
    @dataclass
    class SupervisordConfig:
        unix_http_server: str
        pid_file: str
        workdir: str
        logfile: str

    template = await read_resource(__package__, "supervisord.conf.j2")
    assert template is not None
    template = template.decode("utf8")
    cwd = str(os.getcwd())
    if not supervisord_subprocess_log_dir(config).exists():
        supervisord_subprocess_log_dir(config).mkdir(exist_ok=True)
    config_string = Template(template).render(  # pyright: reportUnknownMemberType=false
        instances=[
            _Instance(  # type: ignore[call-arg]
                type=i.type.name,
                logfile=supervisord_subprocess_log_dir(config) / f"{i.id}.log",
                id=str(i.id),
                workdir=cwd,
                command=_get_command_based_on_type(config, i),
                environment=f"SYSTEMD_INSTANCE={i.id}",
            )
            for i in instances
        ],
        config=SupervisordConfig(  # type: ignore[call-arg]
            unix_http_server=supervisord_sock_file(config),
            pid_file=supervisord_pid_file(config),
            workdir=cwd,
            logfile=supervisord_log_file(config),
        ),
    )
    await writefile(supervisord_config_file_tmp(config), config_string)
    # atomically replace
    os.rename(supervisord_config_file_tmp(config), supervisord_config_file(config))


async def _start_supervisord(config: KresConfig) -> None:
    await _write_config_file(config, set())
    res = await call(f'supervisord --configuration="{supervisord_config_file(config).absolute()}"', shell=True)
    if res != 0:
        raise SubprocessControllerException(f"Supervisord exited with exit code {res}")


async def _stop_supervisord(config: KresConfig) -> None:
    pid = int(await readfile(supervisord_pid_file(config)))
    kill(pid, signal.SIGTERM)
    await wait_for_process_termination(pid)


async def _update_config(config: KresConfig, instances: Set["SupervisordSubprocess"]) -> None:
    await _write_config_file(config, instances)
    await call(f'supervisorctl -c "{supervisord_config_file(config).absolute()}" update', shell=True)


async def _restart(config: KresConfig, id_: KresID) -> None:
    await call(f'supervisorctl -c "{supervisord_config_file(config).absolute()}" restart {id_}', shell=True)


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


def _list_subprocesses(config: KresConfig) -> Dict[KresID, SubprocessStatus]:
    proxy = ServerProxy(
        "http://127.0.0.1",
        transport=supervisor.xmlrpc.SupervisorTransport(
            None, None, serverurl="unix://" + str(supervisord_sock_file(config))
        ),
    )
    processes: Any = proxy.supervisor.getAllProcessInfo()

    def convert(proc: Any) -> SubprocessStatus:
        conversion_tbl = {
            "FATAL": SubprocessStatus.FAILED,
            "EXITED": SubprocessStatus.FAILED,
            "RUNNING": SubprocessStatus.RUNNING,
        }

        if proc["statename"] in conversion_tbl:
            status = conversion_tbl[proc["statename"]]
        else:
            status = SubprocessStatus.UNKNOWN
        return status

    return {SupervisordKresID.from_string(pr["name"]): convert(pr) for pr in processes}


async def _list_ids_from_existing_config(cfg: KresConfig) -> List[SupervisordKresID]:
    config = await readfile(supervisord_config_file(cfg))
    cp = configparser.ConfigParser()
    cp.read_string(config)

    res: List[SupervisordKresID] = []
    for section in cp.sections():
        if section.startswith("program:"):
            program_id = section.replace("program:", "")
            kid = SupervisordKresID.from_string(program_id)
            res.append(kid)
    return res


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

    async def _start(self) -> None:
        return await self._controller.start_subprocess(self)

    async def _stop(self) -> None:
        return await self._controller.stop_subprocess(self)

    async def _restart(self) -> None:
        return await self._controller.restart_subprocess(self)

    def get_used_config(self) -> KresConfig:
        return self._config


class SupervisordSubprocessController(SubprocessController):
    def __init__(self):
        self._running_instances: Set[SupervisordSubprocess] = set()
        self._controller_config: Optional[KresConfig] = None

    def __str__(self):
        return "supervisord"

    def should_be_running(self, subprocess: SupervisordSubprocess) -> bool:
        return subprocess in self._running_instances

    async def is_controller_available(self, config: KresConfig) -> bool:
        res = await _is_supervisord_available()
        if not res:
            logger.info("Failed to find usable supervisord.")

        logger.debug("Detection - supervisord controller is available for use")
        return res

    async def _update_config_with_real_state(self, config: KresConfig) -> None:
        assert self._controller_config is not None

        running = await _is_supervisord_running(config)
        if running:
            ids = await _list_ids_from_existing_config(config)
            for id_ in ids:
                self._running_instances.add(SupervisordSubprocess(self._controller_config, self, id_))

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        assert self._controller_config is not None

        await self._update_config_with_real_state(self._controller_config)
        return iter(self._running_instances)

    async def initialize_controller(self, config: KresConfig) -> None:
        self._controller_config = config

        if not await _is_supervisord_running(config):
            await _start_supervisord(config)

    async def shutdown_controller(self) -> None:
        assert self._controller_config is not None
        await _stop_supervisord(self._controller_config)

    async def start_subprocess(self, subprocess: SupervisordSubprocess) -> None:
        assert self._controller_config is not None
        assert subprocess not in self._running_instances
        self._running_instances.add(subprocess)
        await _update_config(self._controller_config, self._running_instances)

    async def stop_subprocess(self, subprocess: SupervisordSubprocess) -> None:
        assert self._controller_config is not None
        assert subprocess in self._running_instances
        self._running_instances.remove(subprocess)
        await _update_config(self._controller_config, self._running_instances)

    async def restart_subprocess(self, subprocess: SupervisordSubprocess) -> None:
        assert self._controller_config is not None
        assert subprocess in self._running_instances
        await _restart(self._controller_config, subprocess.id)

    async def create_subprocess(self, subprocess_config: KresConfig, subprocess_type: SubprocessType) -> Subprocess:
        return SupervisordSubprocess(subprocess_config, self, subprocess_type)

    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        return await to_thread(_list_subprocesses, self._controller_config)
