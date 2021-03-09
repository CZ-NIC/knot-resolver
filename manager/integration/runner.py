import subprocess
import signal
import uuid
from typing import Optional, List, BinaryIO, Dict
import shutil
import tarfile
import os
import time
import sys
import requests
import hashlib

from _hashlib import HASH as Hash
from pathlib import Path, PurePath
from typing import Union


class DirectoryHash:
    """
    This class serves one purpose - hide implementation details of directory hashing
    """

    @staticmethod
    def _md5_update_from_file(filename: Union[str, Path], hash: Hash) -> Hash:
        assert Path(filename).is_file()
        with open(str(filename), "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash.update(chunk)
        return hash

    @staticmethod
    def md5_file(filename: Union[str, Path]) -> str:
        return str(
            DirectoryHash._md5_update_from_file(filename, hashlib.md5()).hexdigest()
        )

    @staticmethod
    def _md5_update_from_dir(directory: Union[str, Path], hash: Hash) -> Hash:
        assert Path(directory).is_dir()
        for path in sorted(Path(directory).iterdir(), key=lambda p: str(p).lower()):
            hash.update(path.name.encode())
            if path.is_file():
                hash = DirectoryHash._md5_update_from_file(path, hash)
            elif path.is_dir():
                hash = DirectoryHash._md5_update_from_dir(path, hash)
        return hash

    @staticmethod
    def md5_dir(directory: Union[str, Path]) -> str:
        return str(
            DirectoryHash._md5_update_from_dir(directory, hashlib.md5()).hexdigest()
        )


class PodmanService:
    def __init__(self):
        self._process: Optional[subprocess.Popen] = None

    def __enter__(self):
        # run with --log-level=info or --log-level=debug for debugging
        self._process = subprocess.Popen(
            "podman system service tcp:localhost:13579 --time=0", shell=True
        )
        time.sleep(0.5)  # required to prevent connection failures
        return PodmanServiceManager("http://localhost:13579")

    def __exit__(self, ex_type, ex_value, ex_traceback):
        failed_while_running = self._process.poll() is not None
        self._process.send_signal(signal.SIGINT)

        time.sleep(0.5)  # fixes interleaved stacktraces with podman's output

        if failed_while_running:
            raise Exception("Failed to properly start the podman service", ex_value)


class PodmanServiceManager:
    """
    Using HTTP Rest API new in version 2.0. Documentation here:
    https://docs.podman.io/en/latest/_static/api.html
    """

    _API_VERSION = "v1.0.0"
    _HASHFILE_NAME = ".contentshash"

    def __init__(self, url):
        self._url = url

    def _create_url(self, path):
        return self._url + "/" + PodmanServiceManager._API_VERSION + "/" + path

    @staticmethod
    def _create_tar_achive(directory: Path, outfile: Path):
        with tarfile.open(str(outfile), "w:gz") as tar_handle:
            for root, _, files in os.walk(str(directory)):
                for file in files:
                    path = Path(os.path.join(root, file))
                    tar_handle.add(path, arcname=path.relative_to(directory))

    def _api_build_container(self, image_name: str, data: BinaryIO):
        response = requests.post(
            self._create_url("libpod/build"), params=[("t", image_name)], data=data
        )
        response.raise_for_status()

    def _read_and_remove_hashfile(self, context_dir: Path) -> Optional[str]:
        hashfile: Path = context_dir / PodmanServiceManager._HASHFILE_NAME
        if hashfile.exists():
            hash_ = hashfile.read_text("utf8").strip()
            hashfile.unlink()
        else:
            hash_ = "WAS NOT HASHED BEFORE"

        return hash_

    def _create_hashfile(self, context_dir: Path, hash_: str):
        hashfile: Path = context_dir / PodmanServiceManager._HASHFILE_NAME
        with open(hashfile, "w") as f:
            f.write(hash_)

    def build_image(self, context_dir: Path, image: str):
        old_hash = self._read_and_remove_hashfile(context_dir)
        current_hash = DirectoryHash.md5_dir(context_dir) + "_" + image
        if old_hash == current_hash:
            # no rebuild required
            self._create_hashfile(context_dir, current_hash)
            print("\tSkipping container build")
            return

        # create tar archive out of the context_dir (weird, but there is no other way to specify context)
        tar = Path("/tmp/context.tar.gz")
        PodmanServiceManager._create_tar_achive(context_dir, tar)
        try:
            # send the API request
            with open(tar, "rb") as f:
                self._api_build_container(image, f)

        finally:
            # cleanup the tar file
            # tar.unlink()
            pass

        # create hashfile for future caching
        self._create_hashfile(context_dir, current_hash)

    def _api_create_container(
        self, image: str, bind_mount_ro: Dict[PurePath, PurePath] = {}
    ) -> str:
        response = requests.post(
            self._create_url("libpod/containers/create"),
            json={
                "image": image,
                "remove": True,
                "systemd": "true",
                "mounts": [
                    {
                        "destination": str(destination),
                        "options": ["ro"],
                        "source": str(source),
                        "type": "bind",
                    }
                    for source, destination in bind_mount_ro.items()
                ],
            },
        )
        response.raise_for_status()
        return response.json()["Id"]

    def _api_start_container(self, container_id: str):
        response = requests.post(
            self._create_url(f"libpod/containers/{container_id}/start")
        )
        response.raise_for_status()

    def _api_create_exec(self, container_id, command: List[str]) -> str:
        response = requests.post(
            self._create_url(f"libpod/containers/{container_id}/exec"),
            json={
                "AttachStderr": True,
                "AttachStdin": False,
                "AttachStdout": True,
                "Cmd": command,
                "Tty": True,
                "User": "root",
                "WorkingDir": "/",
            },
        )
        response.raise_for_status()
        return response.json()["Id"]

    def _api_start_exec(self, exec_id):
        response = requests.post(
            self._create_url(f"libpod/exec/{exec_id}/start"), json={}
        )
        response.raise_for_status()

    def _api_get_exec_exit_code(self, exec_id) -> int:
        response = requests.get(self._create_url(f"libpod/exec/{exec_id}/json"))
        response.raise_for_status()
        return int(response.json()["ExitCode"])

    def _api_wait_for_container(self, container_id):
        response = requests.post(
            self._create_url(f"libpod/containers/{container_id}/wait"),
            params=[("condition", "exited")],
            timeout=None,
        )
        response.raise_for_status()

    def start_temporary_and_wait(
        self, image: str, command: List[str], bind_mount_ro: Dict[PurePath, PurePath] = {}
    ) -> int:
        # start the container
        container_id = self._api_create_container(image, bind_mount_ro)
        self._api_start_container(container_id)

        # the container is booting, let's give it some time
        time.sleep(0.5)

        # exec the the actual test
        exec_id = self._api_create_exec(container_id, command)
        self._api_start_exec(exec_id)
        test_exit_code = self._api_get_exec_exit_code(exec_id)

        # issue shutdown command to the container
        exec_id = self._api_create_exec(container_id, ["systemctl", "poweroff"])
        self._api_start_exec(exec_id)

        # wait for the container to shutdown completely
        self._api_wait_for_container(container_id)

        return test_exit_code


class Colors:
    RED = "\033[0;31m"
    YELLOW = "\033[0;33m"
    GREEN = "\033[0;32m"
    RESET = "\033[0m"


def _get_git_root() -> PurePath:
    result = subprocess.run("git rev-parse --show-toplevel", shell=True, capture_output=True)
    return PurePath(str(result.stdout, encoding='utf8').strip())

class TestRunner:
    _TEST_DIRECTORY = "tests"
    _TEST_ENTRYPOINT = ["/test/run"]

    @staticmethod
    def _list_tests() -> List[Path]:
        test_dir: Path = Path(".") / TestRunner._TEST_DIRECTORY
        assert test_dir.is_dir()

        return [
            path
            for path in sorted(test_dir.iterdir(), key=lambda p: str(p))
            if path.is_dir()
        ]

    @staticmethod
    def run():
        with PodmanService() as manager:
            for test_path in TestRunner._list_tests():
                test_name = test_path.absolute().name
                print(f"Running test {Colors.YELLOW}{test_name}{Colors.RESET}")
                image = "knot_test_" + test_name
                print("\tBuilding...")
                manager.build_image(test_path, image)
                print("\tRunning...")
                exit_code = manager.start_temporary_and_wait(
                    image,
                    TestRunner._TEST_ENTRYPOINT,
                    bind_mount_ro={
                        _get_git_root(): PurePath('/repo'),
                        test_path.absolute(): '/test'
                    }
                )
                if exit_code == 0:
                    print(f"\t{Colors.GREEN}Test succeeded{Colors.RESET}")
                else:
                    print(
                        f"\t{Colors.RED}Test failed with exit code {exit_code}{Colors.RESET}"
                    )


if __name__ == "__main__":
    TestRunner.run()
