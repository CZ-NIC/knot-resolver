from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union

NoneType = type(None)


def is_optional(tp: Any) -> bool:
    origin = getattr(tp, "__origin__", None)
    args = getattr(tp, "__args__", [])

    return origin == Union and len(args) == 2 and args[1] == NoneType


def is_dict(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Dict, dict)


def is_list(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (List, list)


def is_tuple(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Tuple, tuple)


def is_union(tp: Any) -> bool:
    """Returns False if it is Union but looks like Optional"""
    return not is_optional(tp) and getattr(tp, "__origin__", None) == Union


def get_generic_type_arguments(tp: Any) -> List[Any]:
    return list(getattr(tp, "__args__", []))


def get_generic_type_argument(tp: Any) -> Any:
    """ same as function get_generic_type_arguments, but expects just one type argument"""

    args = get_generic_type_arguments(tp)
    assert len(args) == 1
    return args[0]


T = TypeVar("T")


def get_optional_inner_type(optional: Type[Optional[T]]) -> Type[T]:
    assert is_optional(optional)
    return get_generic_type_arguments(optional)[0]
