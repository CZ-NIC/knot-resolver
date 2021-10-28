# pylint: disable=comparison-with-callable


import enum
import inspect
import sys
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union

from typing_extensions import Literal

NoneType = type(None)


def is_optional(tp: Any) -> bool:
    origin = getattr(tp, "__origin__", None)
    args = get_generic_type_arguments(tp)

    return origin == Union and len(args) == 2 and args[1] == NoneType  # type: ignore


def is_dict(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Dict, dict)


def is_enum(tp: Any) -> bool:
    return inspect.isclass(tp) and issubclass(tp, enum.Enum)


def is_list(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (List, list)


def is_tuple(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Tuple, tuple)


def is_union(tp: Any) -> bool:
    """ Returns true even for optional types, because they are just a Union[T, NoneType] """
    return getattr(tp, "__origin__", None) == Union  # type: ignore


def is_literal(tp: Any) -> bool:
    if sys.version_info.minor == 6:
        return isinstance(tp, type(Literal))
    else:
        return getattr(tp, "__origin__", None) == Literal


def get_generic_type_arguments(tp: Any) -> List[Any]:
    default: List[Any] = []
    if sys.version_info.minor == 6 and is_literal(tp):
        return getattr(tp, "__values__")
    else:
        return getattr(tp, "__args__", default)


def get_generic_type_argument(tp: Any) -> Any:
    """ same as function get_generic_type_arguments, but expects just one type argument"""

    args = get_generic_type_arguments(tp)
    assert len(args) == 1
    return args[0]


def is_none_type(tp: Any) -> bool:
    return tp is None or tp == NoneType


def get_attr_type(obj: Any, attr_name: str) -> Any:
    assert hasattr(obj, attr_name)
    assert hasattr(obj, "__annotations__")
    annot = getattr(type(obj), "__annotations__")
    assert attr_name in annot
    return annot[attr_name]


class _LiteralEnum:
    def __getitem__(self, args: Tuple[Union[str, int, bytes], ...]) -> Any:
        lits = tuple(Literal[x] for x in args)
        return Union[lits]  # type: ignore


LiteralEnum = _LiteralEnum()


T = TypeVar("T")


def get_optional_inner_type(optional: Type[Optional[T]]) -> Type[T]:
    assert is_optional(optional)
    return get_generic_type_arguments(optional)[0]


def is_internal_field_name(field_name: str) -> bool:
    return field_name.startswith("_")
