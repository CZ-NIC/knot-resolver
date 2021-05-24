import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NoReturn, TypeVar

import click
import toml


class Colors:
    RED = "\033[0;31m"
    YELLOW = "\033[0;33m"
    GREEN = "\033[0;32m"
    BRIGHT_BLACK = "\033[0;90m"
    RESET = "\033[0m"


def _get_git_root() -> Path:
    result = subprocess.run(
        "git rev-parse --show-toplevel", shell=True, stdout=subprocess.PIPE
    )
    return Path(str(result.stdout, encoding="utf8").strip())


T = TypeVar("T")
def flatten(lst: List[List[T]]) -> List[T]:
    res: List[T] = []
    for inner in lst:
        res.extend(inner)
    return res


class Test:
    _CONFIG_FILE = "test.toml"

    def __init__(self, path: Path):
        with open(path / Test._CONFIG_FILE, 'r') as f:
            config = toml.load(f)

        self._mounts: Dict[Path, Path] = {}
        gitroot: Path = _get_git_root()
        for dst, src in config["mount"].items():
            # note that we flip the meaning around to match podman's api
            src = gitroot / src
            dst = gitroot / dst
            self._mounts[src] = dst
        
        self.name = str(path.absolute().name)
        self._cmd = [ str(x) for x in config["cmd"] ]
        self._images = [ str(img) for img in config["images"]]

    
    def run(self, inspect_failed: bool =False) -> bool:
        success = True
        for image in self._images:
            print(f"Running test {Colors.YELLOW}{self.name}{Colors.RESET} within container {Colors.YELLOW}{image}{Colors.RESET}")
            print(f"----------------------------{Colors.BRIGHT_BLACK}")
            cmd: List[str] = ["../scripts/container.py", "run"] + (["-i"] if inspect_failed else []) + flatten([["-m", f"{k}:{v}"] for k,v in self._mounts.items()]) + [image] + self._cmd

            # run and relay output
            exit_code = subprocess.call(cmd)
            print(f"{Colors.RESET}----------------------------")
            if exit_code == 0:
                print(f"{Colors.GREEN}Test succeeded{Colors.RESET}")
            else:
                print(
                    f"{Colors.RED}Test failed with exit code {exit_code}{Colors.RESET}"
                )
            success = success and exit_code == 0
        return success

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
    @click.command()
    @click.argument("tests", nargs=-1)
    @click.option(
        "-i",
        "--inspect-failed",
        help="When a test fails, launch an interactive shell in it before termination.",
        default=False,
        is_flag=True,
    )
    @click.option(
        "-n",
        "--no-build",
        help="Skip building the containers",
        default=False,
        is_flag=True,
    )
    def run(tests: List[str] = [], inspect_failed: bool = False, no_build: bool = False) -> NoReturn:
        """Run TESTS

        If no TESTS are specified, runs them all.
        """

        # build all test containers
        if not no_build:
            ret = subprocess.call("poe container build", shell=True)
            assert ret == 0

        # Run the tests
        success = True
        for test_path in TestRunner._list_tests():
            test = Test(test_path)

            if len(tests) != 0 and test.name not in tests:
                print(f"Skipping test {Colors.YELLOW}{test.name}{Colors.RESET}")
                continue

            res = test.run(inspect_failed)
            success = success and res
        
        if not success:
            sys.exit(1)
        else:
            sys.exit(0)


if __name__ == "__main__":
    # before running anything, set correct CWD
    os.chdir(_get_git_root() / "integration")
    # run the tests
    TestRunner.run()
