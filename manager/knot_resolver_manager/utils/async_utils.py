import asyncio
import os
import pkgutil
import time
from asyncio import create_subprocess_exec, create_subprocess_shell
from pathlib import PurePath
from typing import List, Optional, Union

from knot_resolver_manager.compat.asyncio import to_thread


async def call(
    cmd: Union[str, bytes, List[str], List[bytes]], shell: bool = False, discard_output: bool = False
) -> int:
    """
    custom async alternative to subprocess.call()
    """
    kwargs = {}
    if discard_output:
        kwargs["stdout"] = asyncio.subprocess.DEVNULL
        kwargs["stderr"] = asyncio.subprocess.DEVNULL

    if shell:
        if isinstance(cmd, list):
            raise RuntimeError("can't use list of arguments with shell=True")
        proc = await create_subprocess_shell(cmd, **kwargs)
    else:
        if not isinstance(cmd, list):
            raise RuntimeError(
                "Please use list of arguments, not a single string. It will prevent ambiguity when parsing"
            )
        proc = await create_subprocess_exec(*cmd, **kwargs)

    return await proc.wait()


async def readfile(path: Union[str, PurePath]) -> str:
    """
    asynchronously read whole file and return its content
    """

    def readfile_sync(path: Union[str, PurePath]):
        with open(path, "r") as f:
            return f.read()

    return await to_thread(readfile_sync, path)


async def writefile(path: Union[str, PurePath], content: str):
    """
    asynchronously set content of a file to a given string `content`.
    """

    def writefile_sync(path: Union[str, PurePath], content: str):
        with open(path, "w") as f:
            return f.write(content)

    await to_thread(writefile_sync, path, content)


async def wait_for_process_termination(pid: int, sleep_sec: float = 0):
    """
    will wait for any process (does not have to be a child process) given by its PID to terminate

    sleep_sec configures the granularity, with which we should return
    """

    def wait_sync(pid: int, sleep_sec: float):
        while True:
            try:
                os.kill(pid, 0)
                if sleep_sec == 0:
                    os.sched_yield()
                else:
                    time.sleep(sleep_sec)
            except ProcessLookupError:
                break

    await to_thread(wait_sync, pid, sleep_sec)


async def read_resource(package: str, filename: str) -> Optional[bytes]:
    return await to_thread(pkgutil.get_data, package, filename)
