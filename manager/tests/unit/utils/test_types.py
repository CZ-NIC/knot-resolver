from typing import List

from typing_extensions import Literal

from knot_resolver_manager.utils.types import is_list, is_literal


def test_is_list():
    assert is_list(List[str])
    assert is_list(List[int])


def test_is_literal():
    assert is_literal(Literal[5])
    assert is_literal(Literal["test"])
