import asyncio
import os
import pkgutil
import signal
import sys
import time
from asyncio import create_subprocess_exec, create_subprocess_shell
from pathlib import PurePath
from threading import Thread
from typing import Any, Dict, Generic, List, Optional, TypeVar, Union

from knot_resolver_manager.compat.asyncio import to_thread


def unblock_signals():
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, signal.valid_signals())  # type: ignore
    else:
        # the list of signals is not exhaustive, but it should cover all signals we might ever want to block
        signal.pthread_sigmask(
            signal.SIG_UNBLOCK,
            {
                signal.SIGHUP,
                signal.SIGINT,
                signal.SIGTERM,
                signal.SIGUSR1,
                signal.SIGUSR2,
            },
        )


async def call(
    cmd: Union[str, bytes, List[str], List[bytes]], shell: bool = False, discard_output: bool = False
) -> int:
    """
    custom async alternative to subprocess.call()
    """
    kwargs: Dict[str, Any] = {
        "preexec_fn": unblock_signals,
    }
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

    def readfile_sync(path: Union[str, PurePath]) -> str:
        with open(path, "r", encoding="utf8") as f:
            return f.read()

    return await to_thread(readfile_sync, path)


async def writefile(path: Union[str, PurePath], content: str) -> None:
    """
    asynchronously set content of a file to a given string `content`.
    """

    def writefile_sync(path: Union[str, PurePath], content: str) -> int:
        with open(path, "w", encoding="utf8") as f:
            return f.write(content)

    await to_thread(writefile_sync, path, content)


async def wait_for_process_termination(pid: int, sleep_sec: float = 0) -> None:
    """
    will wait for any process (does not have to be a child process) given by its PID to terminate

    sleep_sec configures the granularity, with which we should return
    """

    def wait_sync(pid: int, sleep_sec: float) -> None:
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


T = TypeVar("T")


class BlockingEventDispatcher(Thread, Generic[T]):
    def __init__(self, name: str = "blocking_event_dispatcher") -> None:
        super().__init__(name=name, daemon=True)
        # warning: the asyncio queue is not thread safe
        self._removed_unit_names: "asyncio.Queue[T]" = asyncio.Queue()
        self._main_event_loop = asyncio.get_event_loop()

    def dispatch_event(self, event: T) -> None:
        """
        Method to dispatch events from the blocking thread
        """

        async def add_to_queue():
            await self._removed_unit_names.put(event)

        self._main_event_loop.call_soon_threadsafe(add_to_queue)

    async def next_event(self) -> T:
        return await self._removed_unit_names.get()
