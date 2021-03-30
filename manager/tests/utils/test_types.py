from typing import List

from knot_resolver_manager.utils.types import is_list


def test_is_list():
    assert is_list(List[str])
    assert is_list(List[int])
