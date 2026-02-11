import asyncio
import os
import pkgutil
import signal
import time
from asyncio import create_subprocess_exec, create_subprocess_shell
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from knot_resolver.utils.compat.asyncio import to_thread


async def call(
    cmd: Union[str, bytes, List[str], List[bytes]], shell: bool = False, discard_output: bool = False
) -> int:
    """Async alternative to subprocess.call()."""
    kwargs: Dict[str, Any] = {"preexec_fn": signal.pthread_sigmask(signal.SIG_UNBLOCK, signal.valid_signals())}
    if discard_output:
        kwargs["stdout"] = asyncio.subprocess.DEVNULL
        kwargs["stderr"] = asyncio.subprocess.DEVNULL

    if shell:
        if isinstance(cmd, list):
            msg = "can't use list of arguments with shell=True"
            raise RuntimeError(msg)
        proc = await create_subprocess_shell(cmd, **kwargs)
    else:
        if not isinstance(cmd, list):
            msg = "Please use list of arguments, not a single string. It will prevent ambiguity when parsing"
            raise RuntimeError(msg)
        proc = await create_subprocess_exec(*cmd, **kwargs)

    return await proc.wait()


async def readfile(path: Path) -> str:
    """Asynchronously read file on a path and return its content."""

    def readfile_sync(path: Path) -> str:
        with path.open("r", encoding="utf8") as file:
            return file.read()

    return await to_thread(readfile_sync, path)


async def writefile(path: Path, content: str) -> None:
    """Asynchronously set content of a file on path to a given string content."""

    def writefile_sync(path: Path, content: str) -> int:
        with path.open("w", encoding="utf8") as file:
            return file.write(content)

    await to_thread(writefile_sync, path, content)


async def wait_for_process_termination(pid: int, sleep_sec: float = 0) -> None:
    """
    Wait for any process (does not have to be a child process) given by its PID to terminate.

    Will wait for any process (does not have to be a child process)
    given by its PID to terminate sleep_sec configures the granularity,
    with which we should return.
    """

    def wait_sync(pid: int, sleep_sec: float) -> None:
        try:
            while True:
                os.kill(pid, 0)
                if sleep_sec == 0:
                    os.sched_yield()
                else:
                    time.sleep(sleep_sec)
        except ProcessLookupError:
            pass

    await to_thread(wait_sync, pid, sleep_sec)


async def read_resource(package: str, filename: str) -> Optional[bytes]:
    return await to_thread(pkgutil.get_data, package, filename)
