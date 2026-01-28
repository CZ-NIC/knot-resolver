from typing import Any, Callable, Optional, Type, TypeVar

T = TypeVar("T")


def ignore_exceptions_optional(
    _tp: Type[T], default: Optional[T], *exceptions: Type[BaseException]
) -> Callable[[Callable[..., Optional[T]]], Callable[..., Optional[T]]]:
    """
    Wrap function preventing it from raising exceptions and instead returning the configured default value.

    :param type[T] _tp: Return type of the function. Essentialy only a template argument for type-checking
    :param T default: The value to return as a default
    :param list[Type[BaseException]] exceptions: The list of exceptions to catch
    :return: value of the decorated function, or default if exception raised
    :rtype: T
    """

    def decorator(func: Callable[..., Optional[T]]) -> Callable[..., Optional[T]]:
        def f(*nargs: Any, **nkwargs: Any) -> Optional[T]:
            try:
                return func(*nargs, **nkwargs)
            except BaseException as e:
                if isinstance(e, exceptions):
                    return default
                raise

        return f

    return decorator


def ignore_exceptions(
    default: T, *exceptions: Type[BaseException]
) -> Callable[[Callable[..., Optional[T]]], Callable[..., Optional[T]]]:
    return ignore_exceptions_optional(type(default), default, *exceptions)


def phantom_use(var: Any) -> None:  # pylint: disable=unused-argument
    """
    Consumes argument doing absolutely nothing with it.

    Useful for convincing pylint, that we need the variable even when its unused.
    """
