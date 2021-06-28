import urllib.parse

import requests


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
