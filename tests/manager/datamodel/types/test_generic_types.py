from typing import Any, List, Optional, Union

import pytest
from pytest import raises

from knot_resolver.datamodel.types import ListOrItem
from knot_resolver.utils.modeling import BaseSchema
from knot_resolver.utils.modeling.exceptions import DataValidationError
from knot_resolver.utils.modeling.types import get_generic_type_wrapper_argument


@pytest.mark.parametrize("val", [str, int])
def test_list_or_item_inner_type(val: Any):
    assert get_generic_type_wrapper_argument(ListOrItem[val]) == Union[List[val], val]


@pytest.mark.parametrize(
    "typ,val",
    [
        (int, [1, 65_535, 5353, 5000]),
        (int, 65_535),
        (str, ["string1", "string2"]),
        (str, "string1"),
    ],
)
def test_list_or_item_valid(typ: Any, val: Any):
    class ListOrItemSchema(BaseSchema):
        test: ListOrItem[typ]

    o = ListOrItemSchema({"test": val})
    assert o.test.serialize() == val
    assert o.test.to_std() == val if isinstance(val, list) else [val]

    i = 0
    for item in o.test:
        assert item == val[i] if isinstance(val, list) else val
        i += 1


@pytest.mark.parametrize(
    "typ,val",
    [
        (str, [True, False, True, False]),
        (str, False),
        (bool, [1, 65_535, 5353, 5000]),
        (bool, 65_535),
        (int, "string1"),
        (int, ["string1", "string2"]),
    ],
)
def test_list_or_item_invalid(typ: Any, val: Any):
    class ListOrItemSchema(BaseSchema):
        test: ListOrItem[typ]

    with raises(DataValidationError):
        ListOrItemSchema({"test": val})


def test_list_or_item_empty():
    with raises(ValueError):
        ListOrItem([])
