import random
import sys
from typing import List, Optional

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.types.base_types import IntRangeBase
from knot_resolver_manager.exceptions import KresManagerException


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
        with raises(KresManagerException):
            Test(inval)
