from typing import Any, Callable, Optional, Type, TypeVar

from .dataclasses_nested import dataclass_nested
from .dataclasses_yaml import StrictyamlParser, dataclass_strictyaml, dataclass_strictyaml_schema

T = TypeVar("T")


def ignore_exceptions(
    default: Optional[T], *exceptions: Type[BaseException]
) -> Callable[[Callable[..., Optional[T]]], Callable[..., Optional[T]]]:
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


__all__ = [
    "dataclass_strictyaml_schema",
    "dataclass_strictyaml",
    "StrictyamlParser",
    "ignore_exceptions",
    "dataclass_nested",
    "types",
]
