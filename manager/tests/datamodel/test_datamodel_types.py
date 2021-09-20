import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import (
    AnyPath,
    IPNetwork,
    IPv6Network96,
    Listen,
    ListenType,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.exceptions import KresdManagerException
from knot_resolver_manager.utils import SchemaNode


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
    class TestClass(SchemaNode):
        size: SizeUnit
        time: TimeUnit

    class TestClassStrict(SchemaNode):
        size: int
        time: int

        def _validate(self) -> None:
            pass

    obj = TestClass({"size": "3K", "time": "10m"})
    assert obj.size == SizeUnit("3072B")
    assert obj.time == TimeUnit("10m")

    strict = TestClassStrict(obj)
    assert strict.size == 3 * 1024
    assert strict.time == 10 * 60 * 1000


def test_anypath():
    class Data(SchemaNode):
        p: AnyPath

    assert str(Data({"p": "/tmp"}).p) == "/tmp"


def test_listen():
    o = Listen({"unix-socket": "/tmp"})

    assert o.typ == ListenType.UNIX_SOCKET
    assert o.ip is None
    assert o.port is None
    assert o.unix_socket is not None
    assert o.interface is None

    o = Listen({"interface": "eth0", "port": 56})

    assert o.typ == ListenType.INTERFACE_AND_PORT
    assert o.ip is None
    assert o.port == 56
    assert o.unix_socket is None
    assert o.interface == "eth0"

    o = Listen({"ip": "123.4.5.6", "port": 56})

    assert o.typ == ListenType.IP_AND_PORT
    assert o.ip == ipaddress.ip_address("123.4.5.6")
    assert o.port == 56
    assert o.unix_socket is None
    assert o.interface is None

    # check failure
    with raises(KresdManagerException):
        Listen({"unix-socket": "/tmp", "ip": "127.0.0.1"})


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
