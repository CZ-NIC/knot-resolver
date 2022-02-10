import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types.base_types import IntRangeBase
from knot_resolver_manager.exceptions import KresManagerException


def test_int_range_base():
    class MinTest(IntRangeBase):
        _min = 10

    assert int(MinTest(10)) == 10
    assert int(MinTest(20)) == 20

    with raises(KresManagerException):
        MinTest(9)

    class MaxTest(IntRangeBase):
        _max = 25

    assert int(MaxTest(20)) == 20
    assert int(MaxTest(25)) == 25

    with raises(KresManagerException):
        MaxTest(26)

    class MinMaxTest(IntRangeBase):
        _min = 10
        _max = 25

    assert int(MinMaxTest(10)) == 10
    assert int(MinMaxTest(20)) == 20
    assert int(MinMaxTest(25)) == 25

    with raises(KresManagerException):
        MinMaxTest(9)
    with raises(KresManagerException):
        MinMaxTest(26)
