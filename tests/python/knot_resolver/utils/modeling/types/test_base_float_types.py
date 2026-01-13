import random
import sys
from typing import Any, Optional

import pytest

from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.base_float_types import BaseFloat, BaseFloatRange


@pytest.mark.parametrize("value", [-65.535, -1, 0, 1, 65.535])
def test_base_float(value: int):
    obj = BaseFloat(value)
    obj.validate()
    assert float(obj) == value
    assert int(obj) == int(value)
    assert str(obj) == f"{value}"


@pytest.mark.parametrize("value", [True, False, "1"])
def test_base_float_invalid(value: Any):
    with pytest.raises(DataModelingError):
        BaseFloat(value).validate()


@pytest.mark.parametrize("min,max", [(0.0, None), (None, 0.0), (1.5, 65.535), (-65.535, -1.5)])
def test_base_float_range(min: Optional[float], max: Optional[float]):
    class TestFloatRange(BaseFloatRange):
        if min:
            _min = min
        if max:
            _max = max

    if min:
        obj = TestFloatRange(min)
        obj.validate()
        assert float(obj) == min
        assert int(obj) == int(min)
        assert str(obj) == f"{min}"
    if max:
        obj = TestFloatRange(max)
        obj.validate()
        assert float(obj) == max
        assert int(obj) == int(max)
        assert str(obj) == f"{max}"

    rmin = int(min + 1) if min else -sys.maxsize - 1
    rmax = int(max - 1) if max else sys.maxsize

    n = 100
    values = [float(random.randint(rmin, rmax)) for _ in range(n)]

    for value in values:
        obj = TestFloatRange(value)
        obj.validate()
        assert float(obj) == float(value)
        assert str(obj) == f"{value}"


@pytest.mark.parametrize("min,max", [(0.0, None), (None, 0.0), (1.5, 65.535), (-65.535, -1.5)])
def test_base_float_range_invalid(min: Optional[float], max: Optional[float]):
    class TestFloatRange(BaseFloatRange):
        if min:
            _min = min
        if max:
            _max = max

    n = 100
    invalid_nums = []

    rmin = int(min + 1) if min else -sys.maxsize - 1
    rmax = int(max - 1) if max else sys.maxsize

    invalid_nums.extend([float(random.randint(rmax + 1, sys.maxsize)) for _ in range(n % 2)] if max else [])
    invalid_nums.extend([float(random.randint(-sys.maxsize - 1, rmin - 1)) for _ in range(n % 2)] if max else [])

    for num in invalid_nums:
        with pytest.raises(DataModelingError):
            TestFloatRange(num).validate()
