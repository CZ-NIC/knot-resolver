from __future__ import annotations

import inspect
import sys
from typing import Any, Dict, List, Literal, Tuple, Union, get_args, get_origin

from knot_resolver.utils.modeling.errors import DataAnnotationError
from knot_resolver.utils.modeling.types.base_custom_type import BaseCustomType
from knot_resolver.utils.modeling.types.base_generic_custom_types import (
    BaseGenericCustomTypeWrapper,
    ListOrItem,
    Transformed,
)

# TODO(amrazek): condition can be removed from Python 3.10+
if sys.version_info >= (3, 10):
    from inspect import get_annotations
    from types import UnionType

NoneType = type(None)


def is_transformed(obj: Any) -> bool:
    if get_origin(obj) is Transformed:
        return True
    # TODO(amrazek): can be removed
    # when typing_extensions are not used for Layered/Annotated
    return "Annotated" in str(obj)


def get_transformed_input_type(obj: Any) -> Any:
    if get_origin(obj) is Transformed:
        return get_args(obj)[1]
    # TODO(amrazek): condition can be removed
    # when typing_extensions are not used for Layered/Annotated
    if "Annotated" in str(obj):
        return get_args(obj)[0]
    msg = f"expected 'Layered/Annotated' type, got {obj}"
    raise DataAnnotationError(msg)


def get_transformed_result_type(obj: Any) -> Any:
    if get_origin(obj) is Transformed:
        return get_args(obj)[0]
    # TODO(amrazek): condition can be removed
    # when typing_extensions are not used for Layered/Annotated
    if "Annotated" in str(obj):
        return getattr(obj, "__metadata__", ())[0]
    msg = f"expected 'Layered/Annotated' type, got {obj}"
    raise DataAnnotationError(msg)


def get_annotations(obj: Any) -> dict[Any, Any]:
    if sys.version_info >= (3, 10):
        return get_annotations(obj)
    # TODO(amrazek): can be removed from Python 3.10+
    return obj.__dict__.get("__annotations__", {})


def get_arg(typ: Any) -> Any:
    args = get_args(typ)
    if len(args) == 1:
        return args[0]
    msg = f"expected one generic type argument, got {len(args)}"
    raise DataAnnotationError(msg)


def is_base_generic_type_wrapper(typ: Any) -> bool:
    origin = get_origin(typ)
    return inspect.isclass(origin) and issubclass(origin, BaseGenericCustomTypeWrapper)


def get_base_generic_type_wrapper_argument(typ: type[BaseGenericCustomTypeWrapper[Any]]) -> Any:
    origin = get_origin(typ)
    if not hasattr(origin, "__orig_bases__"):
        msg = f"expected '{BaseGenericCustomTypeWrapper}' type, got {typ}"
        raise DataAnnotationError(msg)

    arg = get_arg(typ)
    orig_bases: list[Any] = getattr(origin, "__orig_bases__", [])[0]
    return get_arg(orig_bases[arg])


def is_base_custom_type(typ: Any) -> bool:
    return inspect.isclass(typ) and issubclass(typ, BaseCustomType)


def is_dict(typ: Any) -> bool:
    return get_origin(typ) in (Dict, dict)


def is_list(typ: Any) -> bool:
    return get_origin(typ) in (List, list)


def is_list_or_item(typ: Any) -> bool:
    origin = get_origin(typ)
    return inspect.isclass(origin) and issubclass(origin, ListOrItem)


def is_literal(typ: Any) -> bool:
    return get_origin(typ) == Literal


def is_none_type(typ: Any) -> bool:
    return typ is None or typ == NoneType


def is_optional(typ: Any) -> bool:
    args = get_args(typ)
    return is_union(typ) and NoneType in args


def is_tuple(typ: Any) -> bool:
    return get_origin(typ) in (Tuple, tuple)


def is_union(typ: Any) -> bool:
    origin = get_origin(typ)
    # TODO(amrazek): condition can be removed from Python 3.10+
    if sys.version_info >= (3, 10):
        return origin in (Union, UnionType)
    return origin == Union


def get_optional_inner_type(optional: Any) -> Any:
    if is_optional(optional):
        args = get_args(optional)
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
