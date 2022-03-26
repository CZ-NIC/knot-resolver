# We disable pylint checks, because it can't find methods in newer Python versions.
#
# pylint: disable=no-member

# We disable pyright checks because it can't find method that don't exist in this Python version
# so the reported error is correct, but due to the version checking conditions, it never happens.
# Due to backporting, we are also using private methods and non-existent members of classes
#
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPrivateUsage=false

import asyncio
import functools
import logging
import sys
from asyncio import AbstractEventLoop, coroutines, events, tasks
from typing import Any, Awaitable, Callable, Coroutine, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def to_thread(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    # version 3.9 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 9:
        return await asyncio.to_thread(func, *args, **kwargs)  # type: ignore[attr-defined]

    # earlier versions, run with default executor
    else:
        loop = asyncio.get_event_loop()
        pfunc = functools.partial(func, *args, **kwargs)
        res = await loop.run_in_executor(None, pfunc)
        return res


def async_in_a_thread(func: Callable[..., T]) -> Callable[..., Coroutine[None, None, T]]:
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        return await to_thread(func, *args, **kwargs)

    return wrapper


def create_task(coro: Awaitable[T], name: Optional[str] = None) -> "asyncio.Task[T]":
    # version 3.8 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro, name=name)  # type: ignore[attr-defined]

    # version 3.7 and higher, call directly without the name argument
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro)  # type: ignore[attr-defined]

    # earlier versions, use older function
    else:
        return asyncio.ensure_future(coro)


def is_event_loop_running() -> bool:
    loop = events._get_running_loop()  # pylint: disable=protected-access
    return loop is not None and loop.is_running()


def run(coro: Awaitable[T], debug: Optional[bool] = None) -> T:
    # Adapted version of this:
    # https://github.com/python/cpython/blob/3.9/Lib/asyncio/runners.py#L8

    # version 3.7 and higher, call directly
    # disabled due to incompatibilities
    if sys.version_info.major >= 3 and sys.version_info.minor >= 7:
        return asyncio.run(coro, debug=debug)  # type: ignore[attr-defined]

    # earlier versions, use backported version of the function
    if events._get_running_loop() is not None:  # pylint: disable=protected-access
        raise RuntimeError("asyncio.run() cannot be called from a running event loop")

    if not coroutines.iscoroutine(coro):
        raise ValueError(f"a coroutine was expected, got {repr(coro)}")

    loop = events.new_event_loop()
    try:
        events.set_event_loop(loop)
        if debug is not None:
            loop.set_debug(debug)
        return loop.run_until_complete(coro)
    finally:
        try:
            _cancel_all_tasks(loop)
            loop.run_until_complete(loop.shutdown_asyncgens())
            if hasattr(loop, "shutdown_default_executor"):
                loop.run_until_complete(loop.shutdown_default_executor())  # type: ignore[attr-defined]
        finally:
            events.set_event_loop(None)
            loop.close()


def _cancel_all_tasks(loop: AbstractEventLoop) -> None:
    # Backported from:
    # https://github.com/python/cpython/blob/3.9/Lib/asyncio/runners.py#L55-L74
    #
    to_cancel = tasks.Task.all_tasks(loop)
    if not to_cancel:
        return

    for task in to_cancel:
        task.cancel()

    if sys.version_info.minor >= 7:
        # since 3.7, the loop argument is implicitely the running loop
        # since 3.10, the loop argument is removed
        loop.run_until_complete(tasks.gather(*to_cancel, return_exceptions=True))
    else:
        loop.run_until_complete(tasks.gather(*to_cancel, loop=loop, return_exceptions=True))

    for task in to_cancel:
        if task.cancelled():
            continue
        if task.exception() is not None:
            loop.call_exception_handler(
                {
                    "message": "unhandled exception during asyncio.run() shutdown",
                    "exception": task.exception(),
                    "task": task,
                }
            )


def add_async_signal_handler(signal: int, callback: Callable[[], Coroutine[Any, Any, None]]) -> None:
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal, lambda: create_task(callback()))


def remove_signal_handler(signal: int) -> bool:
    loop = asyncio.get_event_loop()
    return loop.remove_signal_handler(signal)
