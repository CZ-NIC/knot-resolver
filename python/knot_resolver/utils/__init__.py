from functools import wraps
from typing import Callable, Optional, Tuple, Type, TypeVar, Union

from typing_extensions import ParamSpec

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")


def ignore_exceptions_optional(
    exceptions: Union[Type[BaseException], Tuple[Type[BaseException]]], default: Optional[T]
) -> Callable[[Callable[P, R]], Callable[P, Union[R, Optional[T]]]]:
    """
    Prevent exception(s) from being raised and return the configured default value instead..

    Args:
        exceptions (Tuple[Type[BaseException]]): Exception(s) to catch.
        default (Optional[T]): The default value to return.

    Returns:
        Callable[[Callable[P, R]], Callable[P, Union[R, Optional[T]]]]:
        The value of the decorated function or the default value if an exception is caught.

    """

    def decorator(func: Callable[P, R]) -> Callable[P, Union[T, Optional[R]]]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> Union[T, Optional[R]]:
            try:
                return func(*args, **kwargs)
            except exceptions:
                return default

        return wrapper

    return decorator
