from typing import Any, Callable, Iterable, Optional, Type, TypeVar

from .custom_types import CustomValueType
from .data_parser_validator import Format, SchemaNode

T = TypeVar("T")


def ignore_exceptions_optional(
    _tp: Type[T], default: Optional[T], *exceptions: Type[BaseException]
) -> Callable[[Callable[..., Optional[T]]], Callable[..., Optional[T]]]:
    """
    Decorator, that wraps around a function preventing it from raising exceptions
    and instead returning the configured default value.

    :param Type[T] _tp: Return type of the function. Essentialy only a template argument for type-checking
    :param T default: The value to return as a default
    :param List[Type[BaseException]] exceptions: The list of exceptions to catch
    :return: value of the decorated function, or default if exception raised
    :rtype: T
    """

    def decorator(func: Callable[..., Optional[T]]) -> Callable[..., Optional[T]]:
        def f(*nargs: Any, **nkwargs: Any) -> Optional[T]:
            try:
                return func(*nargs, **nkwargs)
            except BaseException as e:
                if isinstance(e, exceptions):  # pyright: reportUnnecessaryIsInstance=false
                    return default
                else:
                    raise e

        return f

    return decorator


def ignore_exceptions(
    default: T, *exceptions: Type[BaseException]
) -> Callable[[Callable[..., Optional[T]]], Callable[..., Optional[T]]]:
    return ignore_exceptions_optional(type(default), default, *exceptions)


def foldl(oper: Callable[[T, T], T], default: T, arr: Iterable[T]) -> T:
    val = default
    for x in arr:
        val = oper(val, x)
    return val


def contains_element_matching(cond: Callable[[T], bool], arr: Iterable[T]) -> bool:
    return foldl(lambda x, y: x or y, False, map(cond, arr))


__all__ = [
    "Format",
    "CustomValueType",
    "SchemaNode",
]
