import ipaddress

from pytest import raises

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DomainName,
    InterfaceName,
    InterfaceOptionalPort,
    InterfacePort,
    IPAddress,
    IPAddressOptionalPort,
    IPAddressPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    IPv6Network96,
    PortNumber,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.exceptions import KresManagerException
from knot_resolver_manager.utils import SchemaNode


def test_port_number():
    assert PortNumber(1)
    assert PortNumber(65_535)
    assert PortNumber(5353)
    assert PortNumber(5000)

    with raises(KresManagerException):
        PortNumber(0)
    with raises(KresManagerException):
        PortNumber(65_636)
    with raises(KresManagerException):
        PortNumber(-1)


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


def test_interface_name():
    assert InterfaceName("lo")
    assert InterfaceName("eth0")
    assert InterfaceName("wlo1")
    assert InterfaceName("web_ifgrp")
    assert InterfaceName("e8-2")

    with raises(KresManagerException):
        InterfaceName("_lo")
    with raises(KresManagerException):
        InterfaceName("-wlo1")
    with raises(KresManagerException):
        InterfaceName("lo_")
    with raises(KresManagerException):
        InterfaceName("wlo1-")
    with raises(KresManagerException):
        InterfaceName("e8--2")
    with raises(KresManagerException):
        InterfaceName("web__ifgrp")


def test_interface_port():
    o = InterfacePort("lo@5353")
    assert str(o) == "lo@5353"
    assert o == InterfacePort("lo@5353")
    assert str(o.if_name) == "lo"
    assert o.port == PortNumber(5353)

    o = InterfacePort("2001:db8::1000@5001")
    assert str(o) == "2001:db8::1000@5001"
    assert o == InterfacePort("2001:db8::1000@5001")
    assert str(o.addr) == "2001:db8::1000"
    assert o.port == PortNumber(5001)

    with raises(KresManagerException):
        InterfacePort("lo")
    with raises(KresManagerException):
        InterfacePort("53")


def test_interface_optional_port():
    o = InterfaceOptionalPort("lo")
    assert str(o) == "lo"
    assert o == InterfaceOptionalPort("lo")
    assert str(o.if_name) == "lo"
    assert o.port == None

    o = InterfaceOptionalPort("123.4.5.6")
    assert str(o) == "123.4.5.6"
    assert o == InterfaceOptionalPort("123.4.5.6")
    assert str(o.addr) == "123.4.5.6"
    assert o.port == None

    o = InterfaceOptionalPort("lo@5353")
    assert str(o) == "lo@5353"
    assert o == InterfaceOptionalPort("lo@5353")
    assert str(o.if_name) == "lo"
    assert o.port == PortNumber(5353)

    o = InterfaceOptionalPort("2001:db8::1000@5001")
    assert str(o) == "2001:db8::1000@5001"
    assert o == InterfaceOptionalPort("2001:db8::1000@5001")
    assert str(o.addr) == "2001:db8::1000"
    assert o.port == PortNumber(5001)

    with raises(KresManagerException):
        InterfaceOptionalPort("lo@")
    with raises(KresManagerException):
        InterfaceOptionalPort("@53")


def test_ip_address_port():
    class TestSchema(SchemaNode):
        ip_port: IPAddressPort

    o = TestSchema({"ip-port": "123.4.5.6@5353"})
    assert str(o.ip_port) == "123.4.5.6@5353"
    assert o.ip_port == IPAddressPort("123.4.5.6@5353")

    o = TestSchema({"ip-port": "2001:db8::1000@53"})
    assert str(o.ip_port) == "2001:db8::1000@53"
    assert o.ip_port == IPAddressPort("2001:db8::1000@53")

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
