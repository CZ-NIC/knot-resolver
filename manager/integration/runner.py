import subprocess
import signal
import uuid
from typing import Optional, List
import shutil
import pathlib
import tarfile
import os
import time
import sys
import requests

SOCKET_DIR = pathlib.Path("/dev/shm")

class PodmanService:
    def __init__(self):
        self._process: Optional[subprocess.Popen] = None
    def __enter__(self):
        self._process = subprocess.Popen("podman system service tcp:localhost:13579  --log-level=info --time=0", shell=True)
        time.sleep(0.5)  # required to prevent connection
        return PodmanServiceManager("http://localhost:13579")
    def __exit__(self, ex_type, ex_value, ex_traceback):
        failed_while_running = (self._process.poll() is not None)
        self._process.send_signal(signal.SIGINT)

        time.sleep(0.5) # fixes interleaved stacktraces with podman's output

        if failed_while_running:
            raise Exception("Failed to properly start the podman service", ex_value)

class PodmanServiceManager:
    """
    Using HTTP Rest API new in version 2.0. Documentation here:
    https://docs.podman.io/en/latest/_static/api.html
    """
    _API_VERSION = "v1.0.0"

    def __init__(self, url):
        self._url = url

    def _create_url(self, path):
        return self._url + '/' + PodmanServiceManager._API_VERSION + '/' + path
    
    @staticmethod
    def _create_tar_achive(directory: pathlib.Path, outfile: pathlib.Path):
        with tarfile.open(str(outfile), "w:gz") as tar_handle:
            for root, _, files in os.walk(str(directory)):
                for file in files:
                    tar_handle.add(os.path.join(root, file))

    def build_image(self, context_dir: pathlib.Path, image: str):
        # create tar archive out of the context_dir (weird, but there is no other way to specify context)
        tar = pathlib.Path("/tmp/context.tar.gz")
        PodmanServiceManager._create_tar_achive(context_dir, tar)
        try:
            # send the API request
            with open(tar, 'rb') as f:
                response = requests.post(self._create_url('libpod/build'), params=[("t", image)], data=f)
            response.raise_for_status()

        finally:
            # cleanup the tar file
            tar.unlink()

    def start_temporary_and_wait(self, image: str, command: List[str]) -> int:
        # create the container
        response = requests.post(self._create_url('libpod/containers/create'), json={
                "command": command,
                "image": image,
                "remove": True,
            }
        )
        response.raise_for_status()
        container_id = response.json()['Id']

        # start the container
        response = requests.post(self._create_url(f'libpod/containers/{container_id}/start'))
        response.raise_for_status()

        # the container is doing something

        # wait for the container
        response = requests.post(self._create_url(f'libpod/containers/{container_id}/wait'), params=[('condition', 'exited')], timeout=None)
        response.raise_for_status()
        return int(response.text)




def main():
    with PodmanService() as manager:
        IMAGE = "testenv"
        manager.build_image(pathlib.Path("."), IMAGE)
        res = manager.start_temporary_and_wait(IMAGE, ["bash", "-c", "exit 12"])
        print("Exit code", res)


if __name__ == "__main__":
    main()
