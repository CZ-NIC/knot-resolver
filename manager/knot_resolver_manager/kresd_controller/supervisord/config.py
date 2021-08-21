import configparser
import logging
import os
import signal
from os import kill
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple
from xmlrpc.client import ServerProxy

import supervisor.xmlrpc
from jinja2 import Template

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.constants import (
    GC_EXECUTABLE,
    KRES_CACHE_DIR,
    KRES_GC_SUPERVISORD_ARGS,
    KRESD_EXECUTABLE,
    KRESD_SUPERVISORD_ARGS,
    SUPERVISORD_CONFIG_FILE,
    SUPERVISORD_CONFIG_FILE_TMP,
    SUPERVISORD_LOGFILE,
    SUPERVISORD_PID_FILE,
    SUPERVISORD_SOCK,
    SUPERVISORD_SUBPROCESS_LOG_DIR,
)
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessInfo,
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

WATCHDOG_INTERVAL: int = 15

logger = logging.getLogger(__name__)


@dataclass
class SupervisordConfig:
    instances: Set[Subprocess]
    unix_http_server: str = str(SUPERVISORD_SOCK.absolute())
    pid_file: str = str(SUPERVISORD_PID_FILE.absolute())


async def _create_config_file(config: SupervisordConfig):
    template = await read_resource(__package__, "supervisord.conf.j2")
    assert template is not None
    template = template.decode("utf8")
    config_string = Template(template).render(
        config=config,
        gc_args=KRES_GC_SUPERVISORD_ARGS,
        kresd_args=KRESD_SUPERVISORD_ARGS,
        kresd_executable=KRESD_EXECUTABLE,
        gc_executable=GC_EXECUTABLE,
        cache_dir=KRES_CACHE_DIR,
        log_file=SUPERVISORD_LOGFILE,
        workdir=KRES_CACHE_DIR,
        log_dir=SUPERVISORD_SUBPROCESS_LOG_DIR,
    )
    await writefile(SUPERVISORD_CONFIG_FILE_TMP, config_string)
    # atomically replace
    os.rename(SUPERVISORD_CONFIG_FILE_TMP, SUPERVISORD_CONFIG_FILE)


async def start_supervisord(config: SupervisordConfig):
    await _create_config_file(config)
    res = await call(f'supervisord --configuration="{SUPERVISORD_CONFIG_FILE.absolute()}"', shell=True)
    assert res == 0


async def stop_supervisord():
    pid = int(await readfile(SUPERVISORD_PID_FILE))
    kill(pid, signal.SIGINT)
    await wait_for_process_termination(pid)


async def update_config(config: SupervisordConfig):
    await _create_config_file(config)
    await call(f'supervisorctl -c "{SUPERVISORD_CONFIG_FILE.absolute()}" update', shell=True)


async def restart(id_: str):
    await call(f'supervisorctl -c "{SUPERVISORD_CONFIG_FILE.absolute()}" restart {id_}', shell=True)


async def is_supervisord_available() -> bool:
    i = await call("supervisorctl -h > /dev/null", shell=True, discard_output=True)
    i += await call("supervisord -h > /dev/null", shell=True, discard_output=True)
    return i == 0


async def get_supervisord_pid() -> Optional[int]:
    if not Path(SUPERVISORD_PID_FILE).exists():
        return None

    return int(await readfile(SUPERVISORD_PID_FILE))


def is_process_runinng(pid: int) -> bool:
    try:
        # kill with signal 0 is a safe way to test that a process exists
        kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


async def is_supervisord_running() -> bool:
    pid = await get_supervisord_pid()
    if pid is None:
        return False
    elif not is_process_runinng(pid):
        SUPERVISORD_PID_FILE.unlink()
        return False
    else:
        return True


def list_subprocesses() -> List[SubprocessInfo]:
    proxy = ServerProxy(
        "http://127.0.0.1",
        transport=supervisor.xmlrpc.SupervisorTransport(None, None, serverurl="unix://" + str(SUPERVISORD_SOCK)),
    )
    processes: Any = proxy.supervisor.getAllProcessInfo()

    def convert(proc: Any) -> SubprocessInfo:
        conversion_tbl = {
            "FATAL": SubprocessStatus.FAILED,
            "EXITED": SubprocessStatus.FAILED,
            "RUNNING": SubprocessStatus.RUNNING,
        }

        if proc["statename"] in conversion_tbl:
            status = conversion_tbl[proc["statename"]]
        else:
            status = SubprocessStatus.UNKNOWN

        return SubprocessInfo(id=proc["name"], status=status)

    return [convert(pr) for pr in processes]


def create_id(type_name: SubprocessType, id_: object) -> str:
    return f"{type_name.name}_{id_}"


def parse_id(id_: str) -> Tuple[SubprocessType, str]:
    tp, id_ = id_.split("_", maxsplit=1)
    return (SubprocessType[tp], id_)


async def list_ids_from_existing_config() -> List[Tuple[SubprocessType, str]]:
    config = await readfile(SUPERVISORD_CONFIG_FILE)
    cp = configparser.ConfigParser()
    cp.read_string(config)

    res: List[Tuple[SubprocessType, str]] = []
    for section in cp.sections():
        if section.startswith("program:"):
            program_id = section.replace("program:", "")
            res.append(parse_id(program_id))
    return res
