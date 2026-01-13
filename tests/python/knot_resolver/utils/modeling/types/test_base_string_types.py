import random
import string
from typing import Any, Optional

import pytest

from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.base_string_types import BaseString, BaseStringLength, BaseUnit


@pytest.mark.parametrize("value", [-65_535, -1, 0, 1, 65_535, "a", "abcdef"])
def test_base_string(value: str):
    obj = BaseString(value)
    obj.validate()
    assert str(obj) == str(value)


@pytest.mark.parametrize("value", [True, False])
def test_base_string_invalid(value: Any):
    with pytest.raises(DataModelingError):
        BaseString(value).validate()


@pytest.mark.parametrize("min,max", [(None, 100), (10, 20), (50, None)])
def test_base_string_length(min: Optional[int], max: Optional[int]):
    class TestStringLength(BaseStringLength):
        if min:
            _min_bytes = min
        if max:
            _max_bytes = max

    if min:
        rand_str = "".join(random.choices(string.ascii_uppercase + string.digits, k=min))
        obj = TestStringLength(rand_str)
        obj.validate()
        assert str(obj) == f"{rand_str}"
    if max:
        rand_str = "".join(random.choices(string.ascii_uppercase + string.digits, k=max))
        obj = TestStringLength(rand_str)
        obj.validate()
        assert str(obj) == f"{rand_str}"

    rmin = min if min else 1
    rmax = max if max else 200

    n = 100
    values = [
        "".join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(rmin, rmax))) for _ in range(n)
    ]

    for value in values:
        obj = TestStringLength(value)
        obj.validate()
        assert str(obj) == f"{value}"


@pytest.mark.parametrize("min,max", [(None, 100), (10, 20), (50, None)])
def test_base_string_length_invalid(min: Optional[int], max: Optional[int]):
    class TestStringLength(BaseStringLength):
        if min:
            _min_bytes = min
        if max:
            _max_bytes = max

    n = 100
    invalid_strings = []

    rmin = min if min else 1
    rmax = max if max else 200

    invalid_strings.extend(
        [
            "".join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(rmax, rmax + 20)))
            for _ in range(n % 2)
        ]
        if max
        else []
    )
    invalid_strings.extend(
        [
            "".join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(1, rmin)))
            for _ in range(n % 2)
        ]
        if max
        else []
    )

    for invalid_string in invalid_strings:
        with pytest.raises(DataModelingError):
            TestStringLength(invalid_string).validate()


@pytest.mark.parametrize("value", [1000, "1000a", "100b", "10c", "1d"])
def test_base_unit(value: str):
    class TestBaseUnit(BaseUnit):
        _units = {"a": 1, "b": 10, "c": 100, "d": 1000}

    obj = TestBaseUnit(value)
    obj.validate()
    assert int(obj) == 1000


@pytest.mark.parametrize("value", [True, False, "1000aa", "10ab", "1e"])
def test_base_unit_invalid(value: Any):
    class TestBaseUnit(BaseUnit):
        _units = {"a": 1, "b": 10, "c": 100, "d": 1000}

    with pytest.raises(DataModelingError):
        TestBaseUnit(value).validate()
