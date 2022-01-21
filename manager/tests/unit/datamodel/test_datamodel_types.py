import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DomainName,
    InterfaceOptionalPort,
    InterfacePort,
    IPAddress,
    IPAddressOptionalPort,
    IPAddressPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    IPv6Network96,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.exceptions import KresManagerException
from knot_resolver_manager.utils import SchemaNode


def test_size_unit():
    assert SizeUnit("5368709120B") == SizeUnit("5242880K") == SizeUnit("5120M") == SizeUnit("5G")

    with raises(KresManagerException):
        SizeUnit("-5368709120B")
    with raises(KresManagerException):
        SizeUnit(-5368709120)
    with raises(KresManagerException):
        SizeUnit("5120MM")


def test_time_unit():
    assert TimeUnit("1d") == TimeUnit("24h") == TimeUnit("1440m") == TimeUnit("86400s")

    with raises(KresManagerException):
        TimeUnit("-1")
    with raises(KresManagerException):
        TimeUnit(-24)
    with raises(KresManagerException):
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

    with raises(KresManagerException):
        TestSchema({"name": "b@d.domain.com."})


def test_interface_port():
    class TestSchema(SchemaNode):
        interface: InterfacePort

    o = TestSchema({"interface": "lo@5353"})
    assert str(o.interface) == "lo@5353"
    assert o.interface == InterfacePort("lo@5353")

    with raises(KresManagerException):
        TestSchema({"interface": "lo"})
    with raises(KresManagerException):
        TestSchema({"interface": "lo@"})
    with raises(KresManagerException):
        TestSchema({"interface": "lo@-1"})
    with raises(KresManagerException):
        TestSchema({"interface": "lo@65536"})


def test_interface_optional_port():
    class TestSchema(SchemaNode):
        interface: InterfaceOptionalPort

    o = TestSchema({"interface": "lo"})
    assert str(o.interface) == "lo"
    assert o.interface == InterfaceOptionalPort("lo")

    o = TestSchema({"interface": "lo@5353"})
    assert str(o.interface) == "lo@5353"
    assert o.interface == InterfaceOptionalPort("lo@5353")

    with raises(KresManagerException):
        TestSchema({"ip-port": "lo@"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "lo@-1"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "lo@65536"})


def test_ip_address_port():
    class TestSchema(SchemaNode):
        ip_port: IPAddressPort

    o = TestSchema({"ip-port": "123.4.5.6@5353"})
    assert str(o.ip_port) == "123.4.5.6@5353"
    assert o.ip_port == IPAddressOptionalPort("123.4.5.6@5353")

    o = TestSchema({"ip-port": "2001:db8::1000@53"})
    assert str(o.ip_port) == "2001:db8::1000@53"
    assert o.ip_port == IPAddressOptionalPort("2001:db8::1000@53")

    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "2001:db8::1000"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6.7@5000"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "2001:db8::10000@5001"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@-1"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@65536"})


def test_ip_address_optional_port():
    class TestSchema(SchemaNode):
        ip_port: IPAddressOptionalPort

    o = TestSchema({"ip-port": "123.4.5.6"})
    assert str(o.ip_port) == "123.4.5.6"
    assert o.ip_port == IPAddressOptionalPort("123.4.5.6")

    o = TestSchema({"ip-port": "123.4.5.6@5353"})
    assert str(o.ip_port) == "123.4.5.6@5353"
    assert o.ip_port == IPAddressOptionalPort("123.4.5.6@5353")

    o = TestSchema({"ip-port": "2001:db8::1000"})
    assert str(o.ip_port) == "2001:db8::1000"
    assert o.ip_port == IPAddressOptionalPort("2001:db8::1000")

    o = TestSchema({"ip-port": "2001:db8::1000@53"})
    assert str(o.ip_port) == "2001:db8::1000@53"
    assert o.ip_port == IPAddressOptionalPort("2001:db8::1000@53")

    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6.7"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "2001:db8::10000"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@-1"})
    with raises(KresManagerException):
        TestSchema({"ip-port": "123.4.5.6@65536"})


def test_ip_address():
    class TestSchema(SchemaNode):
        ip: IPAddress

    o = TestSchema({"ip": "123.4.5.6"})
    assert str(o.ip) == "123.4.5.6"
    assert o.ip == IPv4Address("123.4.5.6")

    o = TestSchema({"ip": "2001:db8::1000"})
    assert str(o.ip) == "2001:db8::1000"
    assert o.ip == IPv6Address("2001:db8::1000")

    with raises(KresManagerException):
        TestSchema({"ip": "123456"})


def test_network():
    o = IPNetwork("10.11.12.0/24")
    assert o.to_std().prefixlen == 24
    assert o.to_std() == ipaddress.IPv4Network("10.11.12.0/24")

    with raises(KresManagerException):
        # because only the prefix can have non-zero bits
        IPNetwork("10.11.12.13/8")


def test_ipv6_96_network():
    _ = IPv6Network96("fe80::/96")

    with raises(KresManagerException):
        IPv6Network96("fe80::/95")

    with raises(KresManagerException):
        IPv6Network96("10.11.12.3/96")
