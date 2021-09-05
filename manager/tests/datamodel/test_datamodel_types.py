import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import AnyPath, IPAndPort, SizeUnit, TimeUnit
from knot_resolver_manager.utils import DataParser, DataValidationException, DataValidator


def test_size_unit():
    assert (
        SizeUnit(5368709120)
        == SizeUnit("5368709120")
        == SizeUnit("5368709120B")
        == SizeUnit("5242880K")
        == SizeUnit("5120M")
        == SizeUnit("5G")
    )

    with raises(DataValidationException):
        SizeUnit("-5368709120")
    with raises(DataValidationException):
        SizeUnit(-5368709120)
    with raises(DataValidationException):
        SizeUnit("5120MM")


def test_time_unit():
    assert TimeUnit("1d") == TimeUnit("24h") == TimeUnit("1440m") == TimeUnit("86400s") == TimeUnit(86400)

    with raises(DataValidationException):
        TimeUnit("-1")
    with raises(DataValidationException):
        TimeUnit(-24)
    with raises(DataValidationException):
        TimeUnit("1440mm")


def test_parsing_units():
    class TestClass(DataParser):
        size: SizeUnit
        time: TimeUnit

    class TestClassStrict(DataValidator):
        size: int
        time: int

        def _validate(self) -> None:
            pass

    yaml = """
size: 3K
time: 10m
"""

    obj = TestClass.from_yaml(yaml)
    assert obj.size == SizeUnit(3 * 1024)
    assert obj.time == TimeUnit(10 * 60)

    strict = TestClassStrict(obj)
    assert strict.size == 3 * 1024
    assert strict.time == 10 * 60

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.size == b.size == obj.size
    assert a.time == b.time == obj.time


def test_ipandport():
    class Data(DataParser):
        o: IPAndPort
        s: IPAndPort

    val = """
    o:
      ip: "::"
      port: 590
    s: 127.0.0.1@5656
    """

    val = Data.from_yaml(val)

    assert val.o.port == 590
    assert val.o.ip == ipaddress.ip_address("::")
    assert val.s.port == 5656
    assert val.s.ip == ipaddress.ip_address("127.0.0.1")


def test_anypath():
    class Data(DataParser):
        p: AnyPath

    assert str(Data.from_yaml('p: "/tmp"').p) == "/tmp"
