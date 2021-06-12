from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar, Union

from typing_extensions import Literal

NoneType = type(None)


def is_optional(tp: Any) -> bool:
    origin = getattr(tp, "__origin__", None)
    args = get_generic_type_arguments(tp)

    return origin == Union and len(args) == 2 and args[1] == NoneType


def is_dict(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Dict, dict)


def is_list(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (List, list)


def is_tuple(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) in (Tuple, tuple)


def is_union(tp: Any) -> bool:
    """ Returns true even for optional types, because they are just a Union[T, NoneType] """
    return getattr(tp, "__origin__", None) == Union


def is_literal(tp: Any) -> bool:
    return getattr(tp, "__origin__", None) == Literal


def get_generic_type_arguments(tp: Any) -> List[Any]:
    default: List[Any] = []
    return getattr(tp, "__args__", default)


def get_generic_type_argument(tp: Any) -> Any:
    """ same as function get_generic_type_arguments, but expects just one type argument"""

    args = get_generic_type_arguments(tp)
    assert len(args) == 1
    return args[0]


def is_none_type(tp: Any) -> bool:
    return tp is None or tp == NoneType


class _LiteralEnum:
    def __getitem__(self, args: Tuple[Union[str, int, bytes], ...]) -> Any:
        lits = tuple(Literal[x] for x in args)
        return Union[lits]  # pyright: reportGeneralTypeIssues=false


LiteralEnum = _LiteralEnum()


T = TypeVar("T")


def get_optional_inner_type(optional: Type[Optional[T]]) -> Type[T]:
    assert is_optional(optional)
    return get_generic_type_arguments(optional)[0]
