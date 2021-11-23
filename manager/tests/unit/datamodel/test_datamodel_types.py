import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import (
    AnyPath,
    CheckedPath,
    DomainName,
    IPAddress,
    IPAddressPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    IPv6Network96,
    Listen,
    ListenType,
    SizeUnit,
    TimeUnit,
    UncheckedPath,
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
    class TestSchema(SchemaNode):
        size: SizeUnit
        time: TimeUnit

    o = TestSchema({"size": "3K", "time": "10m"})
    assert o.size == SizeUnit("3072B")
    assert o.time == TimeUnit("10m")
    assert o.size.bytes() == 3072
    assert o.time.seconds() == 10 * 60


def test_checked_path():
    class TestSchema(SchemaNode):
        p: CheckedPath

    assert str(TestSchema({"p": "/tmp"}).p) == "/tmp"


def test_domain_name():
    class TestSchema(SchemaNode):
        name: DomainName

    o = TestSchema({"name": "test.domain.com."})
    assert str(o.name) == "test.domain.com."
    assert o.name == DomainName("test.domain.com.")

    o = TestSchema({"name": "test.domain.com"})
    assert str(o.name) == "test.domain.com"
    assert o.name == DomainName("test.domain.com")

    with raises(KresdManagerException):
        TestSchema({"name": "b@d.domain.com."})


def test_ipaddress_port():
    class TestSchema(SchemaNode):
        ip_port: IPAddressPort

    o = TestSchema({"ip-port": "123.4.5.6"})
    assert str(o.ip_port) == "123.4.5.6"
    assert o.ip_port == IPAddressPort("123.4.5.6")

    o = TestSchema({"ip-port": "123.4.5.6@5353"})
    assert str(o.ip_port) == "123.4.5.6@5353"
    assert o.ip_port == IPAddressPort("123.4.5.6@5353")

    o = TestSchema({"ip-port": "2001:db8::1000"})
    assert str(o.ip_port) == "2001:db8::1000"
    assert o.ip_port == IPAddressPort("2001:db8::1000")

    o = TestSchema({"ip-port": "2001:db8::1000@53"})
    assert str(o.ip_port) == "2001:db8::1000@53"
    assert o.ip_port == IPAddressPort("2001:db8::1000@53")

    with raises(KresdManagerException):
        TestSchema({"ip-port": "123.4.5.6.7"})
    with raises(KresdManagerException):
        TestSchema({"ip-port": "2001:db8::10000"})
    with raises(KresdManagerException):
        TestSchema({"ip-port": "123.4.5.6@"})
    with raises(KresdManagerException):
        TestSchema({"ip-port": "123.4.5.6@-1"})
    with raises(KresdManagerException):
        TestSchema({"ip-port": "123.4.5.6@65536"})


def test_ipaddress():
    class TestSchema(SchemaNode):
        ip: IPAddress

    o = TestSchema({"ip": "123.4.5.6"})
    assert str(o.ip) == "123.4.5.6"
    assert o.ip == IPv4Address("123.4.5.6")

    o = TestSchema({"ip": "2001:db8::1000"})
    assert str(o.ip) == "2001:db8::1000"
    assert o.ip == IPv6Address("2001:db8::1000")

    with raises(KresdManagerException):
        TestSchema({"ip": "123456"})


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
    assert o.ip == IPv4Address("123.4.5.6")
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
