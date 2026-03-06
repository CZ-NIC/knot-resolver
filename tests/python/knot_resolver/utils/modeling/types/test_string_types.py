import random
import string
from typing import Any

import pytest

from knot_resolver.utils.modeling.errors import DataModelingError
from knot_resolver.utils.modeling.types.string_types import (
    DomainName,
    EscapedString,
    EscapedStringMin32,
    InterfaceName,
    InterfaceNameIPAddressOptionalPort,
    InterfaceNameIPAddressPort,
    IPAddressEM,
    IPAddressOptionalPort,
    IPAddressPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    IPv6Network,
    IPv6Network96,
    PinSha256,
    SizeUnit,
    TimeUnit,
)


def _rand_domain_name(label_chars: int, levels: int = 1) -> str:
    return "".join(
        ["".join(random.choices(string.ascii_letters + string.digits, k=label_chars)) + "." for i in range(levels)]
    )


@pytest.mark.parametrize(
    "value",
    [
        ".",
        "example.com",
        "_8443._https.example.com.",
        "this.is.example.com.",
        "test.example.com",
        "test-example.com",
        "bücher.com.",
        "příklad.cz",
        _rand_domain_name(63),
        _rand_domain_name(1, 127),
    ],
)
def test_domain_name(value: str):
    obj = DomainName(value)
    assert str(obj) == value
    assert obj == DomainName(value)
    assert obj.punycode() == value.encode("idna").decode("utf-8") if value != "." else "."


@pytest.mark.parametrize(
    "value",
    [
        "test.example..com.",
        "-example.com",
        "-test.example.net",
        "test-.example.net",
        "test.-example.net",
        ".example.net",
        _rand_domain_name(64),
        _rand_domain_name(1, 128),
    ],
)
def test_domain_name_invalid(value: str):
    with pytest.raises(DataModelingError):
        DomainName(value).validate()


@pytest.mark.parametrize(
    "value,escaped",
    [
        ("", r""),
        ("string", r"string"),
        ("\t\n\v", r"\t\n\v"),
        ("\a\b\f\n\r\t\v\\", r"\a\b\f\n\r\t\v\\"),
        # fmt: off
        ("''", r"\'\'"),
        ('""', r"\"\""),
        ("''", r"\'\'"),
        ('""', r"\"\""),
        ('\\"\\"', r"\\\"\\\""),
        ("\\'\\'", r"\\\'\\\'"),
        # fmt: on
    ],
)
def test_escaped_string(value: str, escaped: str):
    obj = EscapedString(value)
    obj.validate()
    assert str(obj) == str(value)
    assert obj.escape() == escaped


@pytest.mark.parametrize("value", [1.1, True, False])
def test_escaped_string_invalid(value: Any):
    with pytest.raises(DataModelingError):
        EscapedString(value).validate()


@pytest.mark.parametrize(
    "value,escaped",
    [
        (
            "\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\",
            r"\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\\a\b\f\n\r\t\v\\",
        ),
    ],
)
def test_escaped_string_min32(value: str, escaped: str):
    obj = EscapedStringMin32(value)
    obj.validate()
    assert str(obj) == str(value)
    assert obj.escape() == escaped


@pytest.mark.parametrize("value", ["shorter than 32 bytes"])
def test_escaped_string_min32_invalid(value: str):
    with pytest.raises(DataModelingError):
        EscapedStringMin32(value).validate()


@pytest.mark.parametrize("value", ["lo", "eth0", "wlo1", "web_ifgrp", "e8-2"])
def test_interface_name(value: str):
    obj = InterfaceName(value)
    obj.validate()
    assert str(obj) == value


@pytest.mark.parametrize("value", ["_lo", "-wlo1", "lo_", "wlo1-", "e8--2", "web__ifgrp"])
def test_interface_name_invalid(value: str):
    with pytest.raises(DataModelingError):
        InterfaceName(value).validate()


@pytest.mark.parametrize("value", ["lo", "123.4.5.6", "lo@5335", "2001:db8::1000@5001"])
def test_interface_name_ip_address_optional_port(value: str):
    obj = InterfaceNameIPAddressOptionalPort(value)
    obj.validate()
    assert str(obj) == value
    assert (
        str(obj.interface_name if obj.interface_name else obj.ip_address) == value.split("@", 1)[0]
        if "@" in value
        else value
    )
    assert str(obj.port) == str(value.split("@", 1)[1] if "@" in value else None)


@pytest.mark.parametrize("value", ["lo@", "@53"])
def test_interface_name_ip_address_optional_port_invalid(value: str):
    with pytest.raises(DataModelingError):
        InterfaceNameIPAddressOptionalPort(value).validate()


@pytest.mark.parametrize("value", ["lo@5335", "2001:db8::1000@5001"])
def test_interface_name_ip_address_port(value: str):
    obj = InterfaceNameIPAddressPort(value)
    obj.validate()
    assert str(obj) == value
    assert str(obj.interface_name if obj.interface_name else obj.ip_address) == value.split("@", 1)[0]
    assert int(obj.port) == int(value.split("@", 1)[1])


@pytest.mark.parametrize("value", ["lo", "2001:db8::1000", "53"])
def test_interface_name_ip_address_port_invalid(value: str):
    with pytest.raises(DataModelingError):
        InterfaceNameIPAddressPort(value).validate()


@pytest.mark.parametrize("value", ["123.4.5.6@5335", "2001:db8::1000@53"])
def test_ip_address_port(value: str):
    obj = IPAddressPort(value)
    obj.validate()
    assert obj == IPAddressPort(value)
    assert str(obj) == value
    assert str(obj.ip_address) == value.split("@", 1)[0]
    assert int(obj.port) == int(value.split("@", 1)[1])


@pytest.mark.parametrize(
    "value", ["123.4.5.6", "2001:db8::1000", "123.4.5.6.7@5000", "2001:db8::10000@5001", "123.4.5.6@"]
)
def test_ip_address_port_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPAddressPort(value).validate()


@pytest.mark.parametrize("value", ["123.4.5.6", "123.4.5.6@5335", "2001:db8::1000", "2001:db8::1000@53"])
def test_ip_address_optional_port(value: str):
    obj = IPAddressOptionalPort(value)
    obj.validate()
    assert obj == IPAddressOptionalPort(value)
    assert str(obj) == value
    assert str(obj.ip_address) == (value.split("@", 1)[0] if "@" in value else value)
    assert str(obj.port) == str(value.split("@", 1)[1] if "@" in value else None)


@pytest.mark.parametrize("value", ["123.4.5.6.7", "2001:db8::10000", "123.4.5.6@", "@55"])
def test_ip_address_optional_port_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPAddressOptionalPort(value).validate()


@pytest.mark.parametrize("value", ["123.4.5.6", "192.168.0.1"])
def test_ipv4_address(value: str):
    obj = IPv4Address(value)
    obj.validate()
    assert str(obj) == value
    assert obj == IPv4Address(value)


@pytest.mark.parametrize("value", ["123456", "2001:db8::1000"])
def test_ipv4_address_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPv4Address(value).validate()


@pytest.mark.parametrize("value", ["2001:db8::1000", "2001:db8:85a3::8a2e:370:7334"])
def test_ipv6_address(value: str):
    obj = IPv6Address(value)
    obj.validate()
    assert str(obj) == value
    assert obj == IPv6Address(value)


@pytest.mark.parametrize("value", ["123.4.5.6", "2001::db8::1000"])
def test_ipv6_address_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPv6Address(value).validate()


@pytest.mark.parametrize("value", ["192.168.0.1!", "2001:db8::1000!"])
def test_ip_address_em(value: str):
    obj = IPAddressEM(value)
    obj.validate()
    assert str(obj) == value
    assert obj == IPAddressEM(value)


@pytest.mark.parametrize("value", ["192.168.0.1", "2001::db8::1000", "192.168.0.1!!", "2001::db8::1000!!"])
def test_ip_address_em_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPAddressEM(value).validate()


@pytest.mark.parametrize("value", ["10.11.12.0/24", "64:ff9b::/96"])
def test_ip_network(value: str):
    obj = IPNetwork(value)
    obj.validate()
    assert str(obj) == value
    assert obj.ip_network.prefixlen == int(value.split("/", 1)[1])


@pytest.mark.parametrize("value", ["10.11.12.13/8", "10.11.12.5/128"])
def test_ip_network_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPNetwork(value).validate()


@pytest.mark.parametrize("value", ["fe80::/64", "64:ff9b::/96"])
def test_ipv6_network(value: str):
    obj = IPv6Network(value)
    obj.validate()
    assert str(obj) == value
    assert obj.ip_network.prefixlen == int(value.split("/", 1)[1])


@pytest.mark.parametrize("value", ["10.11.12.13/8", "10.11.12.5/128"])
def test_ipv6_network_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPv6Network(value).validate()


@pytest.mark.parametrize("value", ["fe80::/96", "64:ff9b::/96"])
def test_ipv6_network_96(value: str):
    obj = IPv6Network96(value)
    obj.validate()
    assert str(obj) == value
    assert obj.ip_network.prefixlen == int(value.split("/", 1)[1])


@pytest.mark.parametrize("value", ["fe80::/95", "10.11.12.3/96", "64:ff9b::1/96"])
def test_ipv6_network_96_invalid(value: str):
    with pytest.raises(DataModelingError):
        IPv6Network96(value).validate()


@pytest.mark.parametrize(
    "value",
    [
        "d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=",
        "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=",
    ],
)
def test_pin_sha256(value: str):
    obj = PinSha256(value)
    obj.validate()
    assert str(obj) == value


@pytest.mark.parametrize(
    "value",
    [
        "d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM==",
        "E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g",
        "!E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=",
        "d6qzRu9zOE",
    ],
)
def test_pin_sha256_invalid(value: str):
    with pytest.raises(DataModelingError):
        PinSha256(value).validate()


@pytest.mark.parametrize("value", ["5368709120B", "5242880K", "5120M", "5G"])
def test_size_unit_valid(value: str):
    obj = SizeUnit(value)
    assert int(obj) == 5_368_709_120
    assert str(obj) == str(value)
    assert obj.bytes() == 5_368_709_120
    assert obj.mbytes() == 5_120


@pytest.mark.parametrize("value", ["-5B", "45745mB"])
def test_size_unit_invalid(value: str):
    with pytest.raises(DataModelingError):
        SizeUnit(value).validate()


@pytest.mark.parametrize("value", ["1d", "24h", "1440m", "86400s", "86400000ms", "86400000000us"])
def test_time_unit(value: str):
    obj = TimeUnit(value)
    obj.validate()
    assert int(obj) == 86_400_000_000
    assert str(obj) == str(value)
    assert obj.seconds() == 86_400
    assert obj.millis() == 86_400_000
    assert obj.micros() == 86_400_000_000


@pytest.mark.parametrize("value", ["-5S", "45745ss"])
def test_time_unit_invalid(value: str):
    with pytest.raises(DataModelingError):
        TimeUnit(value).validate()
