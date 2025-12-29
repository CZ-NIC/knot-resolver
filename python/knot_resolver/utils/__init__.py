from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING, Callable, TypeVar

if TYPE_CHECKING:
    from typing_extensions import ParamSpec

    P = ParamSpec("P")
    R = TypeVar("R")
    T = TypeVar("T")


def ignore_exceptions_optional(
    exceptions: type[BaseException] | tuple[type[BaseException]], default: T | None
) -> Callable[[Callable[P, R]], Callable[P, R | T | None]]:
    """
    Prevent exception(s) from being raised and return the configured default value instead..

    Args:
        exceptions: Exception(s) to catch.
        default: The default value to return.

    Returns:
        The value of the decorated function or the default value if an exception is caught.

    """

    def decorator(func: Callable[P, R]) -> Callable[P, T | (R | None)]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | (R | None):
            try:
                return func(*args, **kwargs)
            except exceptions:
                return default

        return wrapper

    return decorator
