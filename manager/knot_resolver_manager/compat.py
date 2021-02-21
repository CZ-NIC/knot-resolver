# pylint: disable=E1101

from asyncio.futures import Future
import sys
import asyncio
import functools
from typing import Awaitable, Coroutine


def asyncio_to_thread(func, *args, **kwargs) -> Awaitable:
    # version 3.9 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 9:
        return asyncio.to_thread(func, *args, **kwargs)

    # earlier versions, run with default executor
    else:
        loop = asyncio.get_event_loop()
        pfunc = functools.partial(func, *args, **kwargs)
        return loop.run_in_executor(None, pfunc)


def asyncio_create_task(coro: Coroutine, name=None) -> Future:
    # version 3.8 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro, name=name)

    # version 3.7 and higher, call directly without the name argument
    if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
        return asyncio.create_task(coro)

    # earlier versions, use older function
    else:
        return asyncio.ensure_future(coro)


def asyncio_run(coro: Coroutine, debug=None) -> Awaitable:
    # ideally copy-paste of this:
    # https://github.com/python/cpython/blob/3.9/Lib/asyncio/runners.py#L8

    # version 3.7 and higher, call directly
    if sys.version_info.major >= 3 and sys.version_info.minor >= 7:
        return asyncio.run(coro, debug=debug)

    # earlier versions, run with default executor
    else:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro)
