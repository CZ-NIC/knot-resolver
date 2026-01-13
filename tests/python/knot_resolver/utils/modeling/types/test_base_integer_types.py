import random
import sys
from typing import Any, Optional

import pytest

from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.base_integer_types import BaseInteger, BaseIntegerRange


@pytest.mark.parametrize("value", [-65535, -1, 0, 1, 65535])
def test_base_integer(value: int):
    obj = BaseInteger(value)
    obj.validate()
    assert int(obj) == value
    assert str(obj) == f"{value}"


@pytest.mark.parametrize("value", [True, False, "1", 1.1])
def test_base_integer_invalid(value: Any):
    with pytest.raises(DataModelingError):
        BaseInteger(value).validate()


@pytest.mark.parametrize("min,max", [(0, None), (None, 0), (1, 65535), (-65535, -1)])
def test_base_integer_range(min: Optional[int], max: Optional[int]):
    class TestIntegerRange(BaseIntegerRange):
        if min:
            _min = min
        if max:
            _max = max

    if min:
        obj = TestIntegerRange(min)
        obj.validate()
        assert int(obj) == min
        assert str(obj) == f"{min}"
    if max:
        obj = TestIntegerRange(max)
        obj.validate()
        assert int(obj) == max
        assert str(obj) == f"{max}"

    rmin = min if min else -sys.maxsize - 1
    rmax = max if max else sys.maxsize

    n = 100
    values = [random.randint(rmin, rmax) for _ in range(n)]

    for value in values:
        obj = TestIntegerRange(value)
        obj.validate()
        assert str(obj) == f"{value}"


@pytest.mark.parametrize("min,max", [(0, None), (None, 0), (1, 65535), (-65535, -1)])
def test_base_integer_range_invalid(min: Optional[int], max: Optional[int]):
    class TestIntegerRange(BaseIntegerRange):
        if min:
            _min = min
        if max:
            _max = max

    n = 100
    invalid_nums = []

    rmin = min if min else -sys.maxsize - 1
    rmax = max if max else sys.maxsize

    invalid_nums.extend([random.randint(rmax + 1, sys.maxsize) for _ in range(n % 2)] if max else [])
    invalid_nums.extend([random.randint(-sys.maxsize - 1, rmin - 1) for _ in range(n % 2)] if max else [])

    for num in invalid_nums:
        with pytest.raises(DataModelingError):
            TestIntegerRange(num).validate()
