from __future__ import annotations

import inspect
from typing import Any, Dict, List, Literal, Tuple, Union

from knot_resolver.utils.modeling.errors import DataAnnotationError
from knot_resolver.utils.modeling.types.base_generic_types import BaseGenericTypeWrapper

NoneType = type(None)


def get_annotations(obj: Any) -> dict[Any, Any]:
    if hasattr(inspect, "get_annotations"):
        return inspect.get_annotations(obj)
    # TODO: safe to remove in python3.10
    # This fallback only exists for older versions
    return obj.__dict__.get("__annotations__", {})


def get_generic_type_arguments(typ: Any) -> list[Any]:
    return getattr(typ, "__args__", [])


def get_generic_type_argument(typ: Any) -> Any:
    args = get_generic_type_arguments(typ)
    if len(args) == 1:
        return args[0]
    msg = f"expected one generic type argument, got {len(args)}"
    raise DataAnnotationError(msg)


def is_dict(typ: Any) -> bool:
    return getattr(typ, "__origin__", None) in (Dict, dict)


def is_base_generic_type_wrapper(typ: Any) -> bool:
    origin = getattr(typ, "__origin__", None)
    return inspect.isclass(origin) and issubclass(origin, BaseGenericTypeWrapper)


def get_base_generic_type_wrapper_argument(typ: type[BaseGenericTypeWrapper[Any]]) -> Any:
    if not hasattr(typ, "__origin__"):
        msg = ""
        raise DataAnnotationError(msg)

    origin = getattr(typ, "__origin__")
    if not hasattr(origin, "__orig_bases__"):
        msg = ""
        raise DataAnnotationError(msg)

    orig_base: list[Any] = getattr(origin, "__orig_bases__", [])[0]
    arg = get_generic_type_argument(typ)
    return get_generic_type_argument(orig_base[arg])


def is_list(typ: Any) -> bool:
    return getattr(typ, "__origin__", None) in (List, list)


def is_literal(typ: Any) -> bool:
    return getattr(typ, "__origin__", None) == Literal


def is_none_type(typ: Any) -> bool:
    return typ is None or typ == NoneType


def is_optional(typ: Any) -> bool:
    origin = getattr(typ, "__origin__", None)
    args = get_generic_type_arguments(typ)
    optional_len = 2
    return origin == Union and len(args) == optional_len and NoneType in args


def is_tuple(typ: Any) -> bool:
    return getattr(typ, "__origin__", None) in (Tuple, tuple)


def is_union(typ: Any) -> bool:
    return getattr(typ, "__origin__", None) == Union


def get_optional_inner_type(optional: Any) -> Any:
    if is_optional(optional):
        args = get_generic_type_arguments(optional)
        for arg in args:
            if not is_none_type(arg):
                return arg
    msg = "failed to get inner optional type"
    raise DataAnnotationError(msg)


def getattr_type(obj: Any, attr_name: str) -> Any:
    annot = get_annotations(type(obj))
    if hasattr(annot, attr_name):
        return annot[attr_name]
    msg = "attribute name is missing in data annotations"
    raise DataAnnotationError(msg)


def is_attr_name_private(attr_name: str) -> bool:
    return attr_name.startswith("_")
