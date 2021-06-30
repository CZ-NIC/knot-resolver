import json
import multiprocessing
import subprocess
import time
import urllib.parse
from typing import Union

import requests

from knot_resolver_manager import compat
from knot_resolver_manager.datamodel.config import KresConfig
from knot_resolver_manager.server import start_server


class KnotManagerClient:
    def __init__(self, url: str):
        self._url = url

    def _create_url(self, path: str) -> str:
        return urllib.parse.urljoin(self._url, path)

    def stop(self):
        response = requests.post(self._create_url("/stop"))
        print(response.text)

    def set_num_workers(self, n: int):
        response = requests.post(self._create_url("/config/server/instances"), data=str(n))
        print(response.text)

    def wait_for_initialization(self, timeout_sec: float = 5, time_step: float = 0.4):
        started = time.time()
        while True:
            try:
                response = requests.get(self._create_url("/"))
                data = json.loads(response.text)
                if data["status"] == "RUNNING":
                    return
            except BaseException:
                pass

            if time.time() - started > timeout_sec:
                raise TimeoutError("The manager did not start in time")

            time.sleep(time_step)


def count_running_kresds() -> int:
    """
    Inteded use-case is testing... Nothing more

    Looks at running processes in the system and returns the number of kresd instances observed.
    """
    cmd = subprocess.run(
        "ps aux | grep kresd | grep -v grep", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )
    return len(str(cmd.stdout, "utf8").strip().split("\n"))


class _DefaultSentinel:
    pass


_DEFAULT_SENTINEL = _DefaultSentinel()


def start_manager_in_background(
    host: str, port: int, initial_config: Union[None, KresConfig, _DefaultSentinel] = _DEFAULT_SENTINEL
) -> multiprocessing.Process:
    if isinstance(initial_config, _DefaultSentinel):
        p = multiprocessing.Process(target=compat.asyncio.run, args=(start_server(tcp=[(host, port)], unix=[]),))
    else:
        p = multiprocessing.Process(
            target=compat.asyncio.run, args=(start_server(tcp=[(host, port)], unix=[], config=initial_config),)
        )
    p.start()
    return p
