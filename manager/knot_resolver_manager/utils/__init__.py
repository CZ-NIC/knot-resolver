from typing import Any, Callable, Optional, Type, TypeVar

from .dataclasses_parservalidator import DataclassParserValidatorMixin, ValidationException
from .overload import Overloaded

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


__all__ = [
    "ignore_exceptions_optional",
    "ignore_exceptions",
    "types",
    "DataclassParserValidatorMixin",
    "ValidationException",
    "Overloaded",
]
