import ipaddress
from typing import Any

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DomainName,
    InterfaceName,
    InterfaceOptionalPort,
    InterfacePort,
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


@pytest.mark.parametrize("val", [1, 65_535, 5353, 5000])
def test_port_number_valid(val: int):
    assert int(PortNumber(val)) == val


@pytest.mark.parametrize("val", [0, 65_636, -1, "53"])
def test_port_number_invalid(val: Any):
    with raises(KresManagerException):
        PortNumber(val)


@pytest.mark.parametrize("val", ["5368709120B", "5242880K", "5120M", "5G"])
def test_size_unit_valid(val: str):
    o = SizeUnit(val)
    assert int(o) == 5368709120
    assert str(o) == val
    assert o.bytes() == 5368709120


@pytest.mark.parametrize("val", ["-5B", 5, -5242880, "45745mB"])
def test_size_unit_invalid(val: Any):
    with raises(KresManagerException):
        SizeUnit(val)


@pytest.mark.parametrize("val", ["1d", "24h", "1440m", "86400s", "86400000ms"])
def test_time_unit_valid(val: str):
    o = TimeUnit(val)
    assert int(o) == 86400000
    assert str(o) == val
    assert o.seconds() == 86400
    assert o.millis() == 86400000


@pytest.mark.parametrize("val", ["-1", "-24h", "1440mm", 6575, -1440])
def test_time_unit_invalid(val: Any):
    with raises(KresManagerException):
        TimeUnit("-1")


def test_parsing_units():
    class TestSchema(SchemaNode):
        size: SizeUnit
        time: TimeUnit

    o = TestSchema({"size": "3K", "time": "10m"})
    assert o.size == SizeUnit("3072B")
    assert o.time == TimeUnit("600s")
    assert o.size.bytes() == 3072
    assert o.time.seconds() == 10 * 60


def test_checked_path():
    class TestSchema(SchemaNode):
        p: CheckedPath

    assert str(TestSchema({"p": "/tmp"}).p) == "/tmp"


@pytest.mark.parametrize("val", ["example.com.", "test.example.com", "test-example.com"])
def test_domain_name_valid(val: str):
    o = DomainName(val)
    assert str(o) == val
    assert o == DomainName(val)


@pytest.mark.parametrize("val", ["test.example.com..", "-example.com", "test-.example.net"])
def test_domain_name_invalid(val: str):
    with raises(KresManagerException):
        DomainName(val)


@pytest.mark.parametrize("val", ["lo", "eth0", "wlo1", "web_ifgrp", "e8-2"])
def test_interface_name_valid(val: str):
    assert str(InterfaceName(val)) == val


@pytest.mark.parametrize("val", ["_lo", "-wlo1", "lo_", "wlo1-", "e8--2", "web__ifgrp"])
def test_interface_name_invalid(val: Any):
    with raises(KresManagerException):
        InterfaceName(val)


@pytest.mark.parametrize("val", ["lo@5353", "2001:db8::1000@5001"])
def test_interface_port_valid(val: str):
    o = InterfacePort(val)
    assert str(o) == val
    assert o == InterfacePort(val)
    assert str(o.if_name if o.if_name else o.addr) == val.split("@", 1)[0]
    assert o.port == PortNumber(int(val.split("@", 1)[1]))


@pytest.mark.parametrize("val", ["lo", "2001:db8::1000", "53"])
def test_interface_port_invalid(val: Any):
    with raises(KresManagerException):
        InterfacePort(val)


@pytest.mark.parametrize("val", ["lo", "123.4.5.6", "lo@5353", "2001:db8::1000@5001"])
def test_interface_optional_port_valid(val: str):
    o = InterfaceOptionalPort(val)
    assert str(o) == val
    assert o == InterfaceOptionalPort(val)
    assert str(o.if_name if o.if_name else o.addr) == (val.split("@", 1)[0] if "@" in val else val)
    assert o.port == (PortNumber(int(val.split("@", 1)[1])) if "@" in val else None)


@pytest.mark.parametrize("val", ["lo@", "@53"])
def test_interface_optional_port_invalid(val: Any):
    with raises(KresManagerException):
        InterfaceOptionalPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6@5353", "2001:db8::1000@53"])
def test_ip_address_port_valid(val: str):
    o = IPAddressPort(val)
    assert str(o) == val
    assert o == IPAddressPort(val)
    assert str(o.addr) == val.split("@", 1)[0]
    assert o.port == PortNumber(int(val.split("@", 1)[1]))


@pytest.mark.parametrize(
    "val", ["123.4.5.6", "2001:db8::1000", "123.4.5.6.7@5000", "2001:db8::10000@5001", "123.4.5.6@"]
)
def test_ip_address_port_invalid(val: Any):
    with raises(KresManagerException):
        IPAddressPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "123.4.5.6@5353", "2001:db8::1000", "2001:db8::1000@53"])
def test_ip_address_optional_port_valid(val: str):
    o = IPAddressOptionalPort(val)
    assert str(o) == val
    assert o == IPAddressOptionalPort(val)
    assert str(o.addr) == (val.split("@", 1)[0] if "@" in val else val)
    assert o.port == (PortNumber(int(val.split("@", 1)[1])) if "@" in val else None)


@pytest.mark.parametrize("val", ["123.4.5.6.7", "2001:db8::10000", "123.4.5.6@", "@55"])
def test_ip_address_optional_port_invalid(val: Any):
    with raises(KresManagerException):
        IPAddressOptionalPort(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "192.168.0.1"])
def test_ipv4_address_valid(val: str):
    o = IPv4Address(val)
    assert str(o) == val
    assert o == IPv4Address(val)


@pytest.mark.parametrize("val", ["123456", "2001:db8::1000"])
def test_ipv4_address_invalid(val: Any):
    with raises(KresManagerException):
        IPv4Address(val)


@pytest.mark.parametrize("val", ["2001:db8::1000", "2001:db8:85a3::8a2e:370:7334"])
def test_ipv6_address_valid(val: str):
    o = IPv6Address(val)
    assert str(o) == val
    assert o == IPv6Address(val)


@pytest.mark.parametrize("val", ["123.4.5.6", "2001::db8::1000"])
def test_ipv6_address_invalid(val: Any):
    with raises(KresManagerException):
        IPv6Address(val)


@pytest.mark.parametrize("val", ["10.11.12.0/24", "64:ff9b::/96"])
def test_ip_network_valid(val: str):
    o = IPNetwork(val)
    assert str(o) == val
    assert o.to_std().prefixlen == int(val.split("/", 1)[1])
    assert o.to_std() == ipaddress.ip_network(val)


@pytest.mark.parametrize("val", ["10.11.12.13/8", "10.11.12.5/128"])
def test_ip_network_invalid(val: str):
    with raises(KresManagerException):
        IPNetwork(val)


@pytest.mark.parametrize("val", ["fe80::/96", "64:ff9b::/96"])
def test_ipv6_96_network_valid(val: str):
    assert str(IPv6Network96(val)) == val


@pytest.mark.parametrize("val", ["fe80::/95", "10.11.12.3/96", "64:ff9b::1/96"])
def test_ipv6_96_network_invalid(val: Any):
    with raises(KresManagerException):
        IPv6Network96(val)
