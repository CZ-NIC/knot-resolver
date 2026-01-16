# pylint: disable=comparison-with-callable


import enum
import inspect
import sys
from typing import Any, Dict, List, Literal, Optional, Tuple, Type, TypeVar, Union

from .base_generic_type_wrapper import BaseGenericTypeWrapper

NoneType = type(None)


def get_annotations(obj: Any) -> Dict[str, Any]:
    if hasattr(inspect, "get_annotations"):
        return inspect.get_annotations(obj)
    # TODO(bump to py3.10): Safe to remove. This fallback exists for older versions
    return obj.__dict__.get("__annotations__", {})


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
    """Returns true even for optional types, because they are just a Union[T, NoneType]"""
    return getattr(tp, "__origin__", None) == Union  # type: ignore


def is_literal(tp: Any) -> bool:
    if sys.version_info.minor == 6:
        return isinstance(tp, type(Literal))
    return getattr(tp, "__origin__", None) == Literal


def is_generic_type_wrapper(tp: Any) -> bool:
    orig = getattr(tp, "__origin__", None)
    return inspect.isclass(orig) and issubclass(orig, BaseGenericTypeWrapper)


def get_generic_type_arguments(tp: Any) -> List[Any]:
    default: List[Any] = []
    if sys.version_info.minor == 6 and is_literal(tp):
        return getattr(tp, "__values__")
    return getattr(tp, "__args__", default)


def get_generic_type_argument(tp: Any) -> Any:
    """same as function get_generic_type_arguments, but expects just one type argument"""

    args = get_generic_type_arguments(tp)
    assert len(args) == 1
    return args[0]


def get_generic_type_wrapper_argument(tp: Type["BaseGenericTypeWrapper[Any]"]) -> Any:
    assert hasattr(tp, "__origin__")
    origin = getattr(tp, "__origin__")

    assert hasattr(origin, "__orig_bases__")
    orig_base: List[Any] = getattr(origin, "__orig_bases__", [])[0]

    arg = get_generic_type_argument(tp)
    return get_generic_type_argument(orig_base[arg])


def is_none_type(tp: Any) -> bool:
    return tp is None or tp == NoneType


def get_attr_type(obj: Any, attr_name: str) -> Any:
    assert hasattr(obj, attr_name)
    assert hasattr(obj, "__annotations__")
    annot = get_annotations(type(obj))
    assert attr_name in annot
    return annot[attr_name]


T = TypeVar("T")


def get_optional_inner_type(optional: Type[Optional[T]]) -> Type[T]:
    assert is_optional(optional)
    t: Type[T] = get_generic_type_arguments(optional)[0]
    return t


def is_internal_field_name(field_name: str) -> bool:
    return field_name.startswith("_")
