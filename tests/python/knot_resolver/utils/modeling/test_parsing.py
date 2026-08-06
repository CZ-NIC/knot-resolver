import copy
from typing import Any, Dict

import pytest
from pytest import raises

from knot_resolver.utils.modeling.exceptions import DataValidationError
from knot_resolver.utils.modeling.parsing import data_combine

# default data
data_default = {"key1": {"inner11": False}}


@pytest.mark.parametrize(
    "val,res",
    [
        ({"key2": "value"}, {"key1": {"inner11": False}, "key2": "value"}),
        ({"key2": {"inner21": True}}, {"key1": {"inner11": False}, "key2": {"inner21": True}}),
        ({"key1": {"inner12": 5}}, {"key1": {"inner11": False, "inner12": 5}}),
    ],
)
def test_data_combine_valid(val: Dict[Any, Any], res: Dict[Any, Any]) -> None:
    data = copy.deepcopy(data_default)
    assert data_combine(data, val) == res


@pytest.mark.parametrize("val", [{"key1": "value"}, {"key1": {"inner11": False}}])
def test_data_combine_invalid(val: Dict[Any, Any]) -> None:
    data = copy.deepcopy(data_default)
    with raises(DataValidationError):
        data_combine(data, val)
