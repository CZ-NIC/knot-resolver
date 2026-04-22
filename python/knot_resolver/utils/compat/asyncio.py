import asyncio
import functools
import logging
import sys
from typing import Any, Callable, Coroutine, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


async def to_thread(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    # version 3.9 and higher, call directly
    if sys.version_info >= (3, 9):
        return await asyncio.to_thread(func, *args, **kwargs)
    # earlier versions, run with default executor
    loop = asyncio.get_event_loop()
    pfunc = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(None, pfunc)


def async_in_a_thread(func: Callable[..., T]) -> Callable[..., Coroutine[None, None, T]]:
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        return await to_thread(func, *args, **kwargs)

    return wrapper


def add_async_signal_handler(signal: int, callback: Callable[[], Coroutine[Any, Any, None]]) -> None:
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal, lambda: asyncio.create_task(callback()))


def remove_signal_handler(signal: int) -> bool:
    loop = asyncio.get_event_loop()
    return loop.remove_signal_handler(signal)


def is_event_loop_running() -> bool:
    loop = asyncio.events._get_running_loop()  # noqa: SLF001
    return loop is not None and loop.is_running()
