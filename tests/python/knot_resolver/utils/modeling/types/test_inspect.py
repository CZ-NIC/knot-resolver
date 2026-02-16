import sys
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import pytest

from knot_resolver.utils.modeling.types.base_custom_type import BaseCustomType
from knot_resolver.utils.modeling.types.base_generic_custom_types import (
    ListOrItem,
    Transformed,
)
from knot_resolver.utils.modeling.types.inspect import (
    NoneType,
    is_base_custom_type,
    is_base_generic_type_wrapper,
    is_dict,
    is_list,
    is_list_or_item,
    is_literal,
    is_none_type,
    is_optional,
    is_transformed,
    is_tuple,
    is_union,
)

types = [
    Any,
    bool,
    int,
    float,
    str,
    BaseCustomType,
]

literals = [
    Literal[Any],
    Literal[True, False],
    Literal[0],
    Literal[1, 2, 3],
    Literal["literal"],
    Literal["literal1", "literal2", "literal3"],
]


def test_is_base_custom_type() -> None:
    class TestType(BaseCustomType):
        pass

    assert is_base_custom_type(TestType)


@pytest.mark.parametrize("typ", types)
def test_is_base_generic_custom_type_wrapper(typ: Any) -> None:
    assert is_base_generic_type_wrapper(ListOrItem[typ])


@pytest.mark.parametrize("typ", types)
def test_is_dict(typ: Any) -> None:
    assert is_dict(Dict[typ, Any])


def test_is_transformed():
    typ = Transformed[int, float]
    assert is_transformed(typ)


@pytest.mark.parametrize("typ", types)
def test_is_list(typ: Any) -> None:
    assert is_list(List[typ])
    if sys.version_info >= (3, 10):
        assert is_list(list[typ])


@pytest.mark.parametrize("typ", types)
def test_is_list_or_item(typ: Any) -> None:
    assert is_list_or_item(ListOrItem[typ])


@pytest.mark.parametrize("typ", literals)
def test_is_literal(typ: Any) -> None:
    assert is_literal(typ)


@pytest.mark.parametrize("typ", [None, NoneType])
def test_is_none_type(typ: Any) -> None:
    assert is_none_type(typ)


@pytest.mark.parametrize("typ", types)
def test_is_optional(typ: Any) -> None:
    assert is_optional(Optional[typ])
    if sys.version_info >= (3, 10):
        assert is_optional(typ | None)
        assert is_optional(None | typ)


@pytest.mark.parametrize("typ", types)
def test_is_tuple(typ: Any) -> None:
    assert is_tuple(Tuple[typ])
    if sys.version_info >= (3, 10):
        assert is_tuple(tuple[typ])


@pytest.mark.parametrize("typ", types)
def test_is_union(typ: Any) -> None:
    assert is_union(Optional[typ])
    assert is_union(Union[typ, None])
    assert is_union(Union[None, typ])
    if sys.version_info >= (3, 10):
        assert is_union(typ | None)
        assert is_union(None | typ)
