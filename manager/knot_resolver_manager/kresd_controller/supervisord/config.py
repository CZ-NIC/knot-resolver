import os.path
import signal
from os import kill
from pathlib import Path
from time import sleep
from typing import List

from jinja2 import Template

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.async_utils import call, readfile, wait_for_process_termination, writefile

CONFIG_FILE = "/tmp/knot-resolver-manager-supervisord.conf"
PID_FILE = "/tmp/knot-resolver-manager-supervisord.pid"
SERVER_SOCK = "/tmp/knot-resolver-manager-supervisord.sock"


@dataclass
class SupervisordConfig:
    instances: List[str]
    unix_http_server: str = SERVER_SOCK
    pid_file: str = PID_FILE


async def _create_config_file(config: SupervisordConfig):
    path = Path(os.path.realpath(__file__)).parent / "supervisord.conf.j2"
    template = await readfile(path)
    config_string = Template(template).render(config=config)
    await writefile(CONFIG_FILE, config_string)


async def start_supervisord(config: SupervisordConfig):
    await _create_config_file(config)
    await call(f'supervisord --configuration="{CONFIG_FILE}"', shell=True)


async def stop_supervisord():
    pid = int(await readfile(PID_FILE))
    kill(pid, signal.SIGINT)
    await wait_for_process_termination(pid)


async def update_config(config: SupervisordConfig):
    await _create_config_file(config)
    await call(f'supervisorctl -c "{CONFIG_FILE}" update', shell=True)


async def restart(id_: str):
    await call(f'supervisorctl -c "{CONFIG_FILE}" restart {id_}', shell=True)


async def is_supervisord_available() -> bool:
    i = await call("supervisorctl -h > /dev/null", shell=True, discard_output=True)
    i += await call("supervisord -h > /dev/null", shell=True, discard_output=True)
    return i == 0


async def is_supervisord_running() -> bool:
    if not Path(PID_FILE).exists():
        return False

    pid = int(await readfile(PID_FILE))
    try:
        kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


async def list_ids_from_existing_config() -> List[str]:
    config = await readfile(CONFIG_FILE)
    res: List[str] = []
    for line in config.splitlines():
        if line.startswith("[program:"):
            id_ = line.replace("[program:", "").replace("]", "").strip()
            res.append(id_)
    return res
