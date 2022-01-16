from typing import List, Union

from typing_extensions import Literal

from knot_resolver_manager.utils.types import LiteralEnum, is_list


def test_is_list():
    assert is_list(List[str])
    assert is_list(List[int])


def test_literal_enum():
    assert LiteralEnum[5, "test"] == Union[Literal[5], Literal["test"]]
    assert LiteralEnum["str", 5] == Union[Literal["str"], Literal[5]]
