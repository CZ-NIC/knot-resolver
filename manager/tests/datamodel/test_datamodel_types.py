import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import (
    AnyPath,
    IPNetwork,
    IPv6Network96,
    Listen,
    ListenStrict,
    ListenType,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.exceptions import KresdManagerException
from knot_resolver_manager.utils import DataParser, DataValidator


def test_size_unit():
    assert SizeUnit("5368709120B") == SizeUnit("5242880K") == SizeUnit("5120M") == SizeUnit("5G")

    with raises(KresdManagerException):
        SizeUnit("-5368709120B")
    with raises(KresdManagerException):
        SizeUnit(-5368709120)
    with raises(KresdManagerException):
        SizeUnit("5120MM")


def test_time_unit():
    assert TimeUnit("1d") == TimeUnit("24h") == TimeUnit("1440m") == TimeUnit("86400s")

    with raises(KresdManagerException):
        TimeUnit("-1")
    with raises(KresdManagerException):
        TimeUnit(-24)
    with raises(KresdManagerException):
        TimeUnit("1440mm")

    assert TimeUnit("10ms").millis() == 10


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
    assert obj.size == SizeUnit("3072B")
    assert obj.time == TimeUnit("10m")

    strict = TestClassStrict(obj)
    assert strict.size == 3 * 1024
    assert strict.time == 10 * 60 * 1000

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.size == b.size == obj.size
    assert a.time == b.time == obj.time


def test_anypath():
    class Data(DataParser):
        p: AnyPath

    assert str(Data.from_yaml('p: "/tmp"').p) == "/tmp"


def test_listen():
    o = Listen.from_yaml('unix-socket: "/tmp"')
    oo = ListenStrict(o)

    assert oo.typ == ListenType.UNIX_SOCKET
    assert oo.ip is None
    assert oo.port is None
    assert oo.unix_socket is not None
    assert oo.interface is None

    o = Listen.from_yaml('interface: "eth0"')
    oo = ListenStrict(o)

    assert oo.typ == ListenType.INTERFACE
    assert oo.ip is None
    assert oo.port is None
    assert oo.unix_socket is None
    assert oo.interface == "eth0"

    o = Listen.from_yaml(
        """
    ip: 123.4.5.6
    port: 56
    """
    )
    oo = ListenStrict(o)

    assert oo.typ == ListenType.IP_AND_PORT
    assert oo.ip == ipaddress.ip_address("123.4.5.6")
    assert oo.port == 56
    assert oo.unix_socket is None
    assert oo.interface is None

    # check failure
    o = Listen.from_yaml(
        """
        unix-socket: '/tmp'
        ip: 127.0.0.1
    """
    )
    with raises(KresdManagerException):
        ListenStrict(o)


def test_network():
    o = IPNetwork("10.11.12.0/24")
    assert o.to_std().prefixlen == 24
    assert o.to_std() == ipaddress.IPv4Network("10.11.12.0/24")

    with raises(KresdManagerException):
        # because only the prefix can have non-zero bits
        IPNetwork("10.11.12.13/8")


def test_ipv6_96_network():
    _ = IPv6Network96("fe80::/96")

    with raises(KresdManagerException):
        IPv6Network96("fe80::/95")

    with raises(KresdManagerException):
        IPv6Network96("10.11.12.3/96")
