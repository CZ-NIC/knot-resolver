# We disable pylint checks, because it can't find methods in newer Python versions.
#
# pylint: disable=no-member

# We disable pyright checks because it can't find method that don't exist in this Python version
# so the reported error is correct, but due to the version checking conditions, it never happens
#
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownVariableType=false
# pyright: reportGeneralTypeIssues=false

import asyncio
import functools
import logging
import sys
from asyncio.futures import Future
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
        exc: Optional[BaseException] = None

        def exc_catcher():
            nonlocal exc

            try:
                return pfunc()
            except BaseException as e:
                logger.error("Task in thread failed...", exc_info=True)
                exc = e
                return None

        res = await loop.run_in_executor(None, exc_catcher)
        # propagate exception in this thread
        if exc is not None:
            raise exc
        return res


def create_task(coro: Awaitable[T], name: Optional[str] = None) -> "Future[T]":
    # version 3.8 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro, name=name)  # type: ignore[attr-defined]

    # version 3.7 and higher, call directly without the name argument
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro)  # type: ignore[attr-defined]

    # earlier versions, use older function
    else:
        return asyncio.ensure_future(coro)


def run(coro: Awaitable[T], debug: Optional[bool] = None) -> Awaitable[T]:
    # ideally copy-paste of this:
    # https://github.com/python/cpython/blob/3.9/Lib/asyncio/runners.py#L8

    # version 3.7 and higher, call directly
    # disabled due to incompatibilities
    # if sys.version_info.major >= 3 and sys.version_info.minor >= 7 and False:
    #    return asyncio.run(coro, debug=debug)
    # else:
    # earlier versions, run with default executor
    # Explicitelly create a new loop to match behaviour of asyncio.run
    loop = asyncio.events.new_event_loop()
    asyncio.set_event_loop(loop)
    if debug is not None:
        loop.set_debug(debug)
    # The following line have a really weird type requirements. I don't understand the reasoning, but it works
    return loop.run_until_complete(coro)  # type: ignore[arg-type]
    # asyncio.run would cancel all running tasks, but it would use internal API for that
    # so let's ignore it and let the tasks die


def add_async_signal_handler(signal: int, callback: Callable[[], Coroutine[Any, Any, None]]) -> None:
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal, lambda: create_task(callback()))
