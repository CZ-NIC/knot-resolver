import json
import multiprocessing
import subprocess
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Union
import ipaddress

import requests

from knot_resolver_manager import compat
from knot_resolver_manager.server import start_server
from knot_resolver_manager.utils.parsing import ParsedTree


class KnotManagerClient:
    def __init__(self, url: str):
        self._url = url

    def _create_url(self, path: str) -> str:
        return urllib.parse.urljoin(self._url, path)

    def stop(self):
        response = requests.post(self._create_url("/stop"))
        print(response.text)

    def set_num_workers(self, n: int):
        response = requests.post(self._create_url("/config/server/workers"), data=str(n))
        print(response.text)
    
    def set_static_hints(self, hints: Dict[str, List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]]):
        payload = [
            {
                "name": name,
                "addresses": [str(a) for a in addrs]
            }
            for name, addrs in hints.items()
        ]
        response = requests.post(self._create_url("/config/static-hints/hints"), json=payload)
        print(response.text)
    
    def set_listen_ip_address(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], port: int):
        payload = [
            {
                "listen": {
                    "ip": str(ip),
                    "port": port
                }
            }
        ]
        response = requests.post(self._create_url("/config/network/interfaces"), json=payload)
        print(response)

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
    initial_config: Union[Path, ParsedTree, _DefaultSentinel] = _DEFAULT_SENTINEL
) -> multiprocessing.Process:
    if isinstance(initial_config, _DefaultSentinel):
        p = multiprocessing.Process(target=compat.asyncio.run, args=(start_server(),))
    else:
        p = multiprocessing.Process(target=compat.asyncio.run, args=(start_server(config=initial_config),))
    p.start()
    return p
