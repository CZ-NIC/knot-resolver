from typing import Any, List, Union

import pytest

from knot_resolver.utils.modeling.types.base_generic_custom_types import ListOrItem, Transformed
from knot_resolver.utils.modeling.types.inspect import (
    get_base_generic_type_wrapper_argument,
    get_transformed_input_type,
    get_transformed_result_type,
)


@pytest.mark.parametrize("input_t,result_t", [(str, int), (float, bool)])
def test_transformed_inner(input_t: Any, result_t: Any):
    typ = Transformed[input_t, result_t]
    assert get_transformed_input_type(typ) == input_t
    assert get_transformed_result_type(typ) == result_t


@pytest.mark.parametrize("typ", [str, int, float, bool])
def test_list_or_item_inner_type(typ: Any):
    assert get_base_generic_type_wrapper_argument(ListOrItem[typ]) == Union[List[typ], typ]


@pytest.mark.parametrize(
    "value",
    [
        [],
        65_535,
        [1, 65_535, 5335, 5000],
    ],
)
def test_list_or_item(value: Any):
    obj = ListOrItem(value)
    assert str(obj) == str(value)
    for i, item in enumerate(obj):
        assert item == value[i] if isinstance(value, list) else value
