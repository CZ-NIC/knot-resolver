import random
import sys
from typing import List, Optional

import pytest
from pytest import raises

from knot_resolver import KresBaseException
from knot_resolver.datamodel.types.base_types import FloatRangeBase, IntRangeBase, StringLengthBase


@pytest.mark.parametrize("min,max", [(0, None), (None, 0), (1, 65535), (-65535, -1)])
def test_int_range_base(min: Optional[int], max: Optional[int]):
    class Test(IntRangeBase):
        if min:
            _min = min
        if max:
            _max = max

    if min:
        assert int(Test(min)) == min
    if max:
        assert int(Test(max)) == max

    rmin = min if min else -sys.maxsize - 1
    rmax = max if max else sys.maxsize

    n = 100
    vals: List[int] = [random.randint(rmin, rmax) for _ in range(n)]
    assert [str(Test(val)) == f"{val}" for val in vals]

    invals: List[int] = []
    invals.extend([random.randint(rmax + 1, sys.maxsize) for _ in range(n % 2)] if max else [])
    invals.extend([random.randint(-sys.maxsize - 1, rmin - 1) for _ in range(n % 2)] if max else [])

    for inval in invals:
        with raises(KresBaseException):
            Test(inval)


@pytest.mark.parametrize("min,max", [(0.0, None), (None, 0.0), (1.0, 65535.0), (-65535.0, -1.0)])
def test_float_range_base(min: Optional[float], max: Optional[float]):
    class Test(FloatRangeBase):
        if min:
            _min = min
        if max:
            _max = max

    if min:
        assert float(Test(min)) == min
    if max:
        assert float(Test(max)) == max

    rmin = min if min else sys.float_info.min - 1.0
    rmax = max if max else sys.float_info.max

    n = 100
    vals: List[float] = [random.uniform(rmin, rmax) for _ in range(n)]
    assert [str(Test(val)) == f"{val}" for val in vals]

    invals: List[float] = []
    invals.extend([random.uniform(rmax + 1.0, sys.float_info.max) for _ in range(n % 2)] if max else [])
    invals.extend([random.uniform(sys.float_info.min - 1.0, rmin - 1.0) for _ in range(n % 2)] if max else [])

    for inval in invals:
        with raises(KresBaseException):
            Test(inval)


@pytest.mark.parametrize("min,max", [(10, None), (None, 10), (2, 32)])
def test_str_bytes_length_base(min: Optional[int], max: Optional[int]):
    class Test(StringLengthBase):
        if min:
            _min_bytes = min
        if max:
            _max_bytes = max

    if min:
        assert len(str(Test("x" * min)).encode("utf-8")) == min
    if max:
        assert len(str(Test("x" * max)).encode("utf-8")) == max

    n = 100
    rmin = 1 if not min else min
    rmax = 1024 if not max else max
    vals: List[str] = ["x" * random.randint(rmin, rmax) for _ in range(n)]
    assert [str(Test(val)) == f"{val}" for val in vals]

    invals: List[str] = []
    invals.extend(["x" * random.randint(rmax + 1, 2048) for _ in range(n % 2)] if max else [])
    invals.extend(["x" * random.randint(1, rmin - 1) for _ in range(n % 2)] if max else [])

    for inval in invals:
        with raises(KresBaseException):
            Test(inval)
