import sys
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import pytest

from knot_resolver.utils.modeling import ModelNode
from knot_resolver.utils.modeling.types.base_types import BaseType
from knot_resolver.utils.modeling.types.inspect import (
    NoneType,
    is_dict,
    is_list,
    is_literal,
    is_none_type,
    is_optional,
    is_tuple,
    is_union,
)

types = [
    Any,
    bool,
    int,
    float,
    str,
    BaseType,
    ModelNode,
]

literals = [
    Literal[Any],
    Literal[True, False],
    Literal[0],
    Literal[1, 2, 3],
    Literal["literal"],
    Literal["literal1", "literal2", "literal3"],
]


@pytest.mark.parametrize("typ", types)
def test_is_dict(typ: Any) -> None:
    assert is_dict(Dict[typ, Any])


@pytest.mark.parametrize("typ", types)
def test_is_list(typ: Any) -> None:
    assert is_list(List[typ])
    if sys.version_info >= (3, 9):
        assert is_list(list[typ])


@pytest.mark.parametrize("typ", literals)
def test_is_literal(typ: Any) -> None:
    assert is_literal(typ)


@pytest.mark.parametrize("typ", [None, NoneType])
def test_is_none_type(typ: Any) -> None:
    assert is_none_type(typ)


@pytest.mark.parametrize("typ", types)
def test_is_optional(typ: Any) -> None:
    assert is_optional(Optional[typ])
    if sys.version_info >= (3, 9):
        assert is_optional(typ | None)
        assert is_optional(None | typ)


@pytest.mark.parametrize("typ", types)
def test_is_tuple(typ: Any) -> None:
    assert is_tuple(Tuple[typ])
    if sys.version_info >= (3, 9):
        assert is_tuple(tuple[typ])


@pytest.mark.parametrize("typ", types)
def test_is_union(typ: Any) -> None:
    assert is_union(Optional[typ])
    assert is_union(Union[typ, None])
    if sys.version_info >= (3, 9):
        assert is_union(typ | None)
        assert is_union(None | typ)
