import ipaddress
import re
from typing import Any, Dict, Optional, Type, Union

from knot_resolver.datamodel.types.base_types import IntRangeBase, PatternBase, StrBase, StringLengthBase, UnitBase
from knot_resolver.utils.modeling import BaseValueType


class IntNonNegative(IntRangeBase):
    _min: int = 0


class IntPositive(IntRangeBase):
    _min: int = 1


class Int0_32(IntRangeBase):  # noqa: N801
    _min: int = 0
    _max: int = 32


class Int0_512(IntRangeBase):  # noqa: N801
    _min: int = 0
    _max: int = 512


class Int0_65535(IntRangeBase):  # noqa: N801
    _min: int = 0
    _max: int = 65_535


class Percent(IntRangeBase):
    _min: int = 0
    _max: int = 100


class PortNumber(IntRangeBase):
    _min: int = 1
    _max: int = 65_535

    @classmethod
    def from_str(cls: Type["PortNumber"], port: str, object_path: str = "/") -> "PortNumber":
        try:
            return cls(int(port), object_path)
        except ValueError as e:
            raise ValueError(f"invalid port number {port}") from e


class SizeUnit(UnitBase):
    _units = {"B": 1, "K": 1024, "M": 1024**2, "G": 1024**3}

    def bytes(self) -> int:
        return self._base_value

    def mbytes(self) -> int:
        return self._base_value // 1024**2


class TimeUnit(UnitBase):
    _units = {"us": 1, "ms": 10**3, "s": 10**6, "m": 60 * 10**6, "h": 3600 * 10**6, "d": 24 * 3600 * 10**6}

    def minutes(self) -> int:
        return self._base_value // 1000**2 // 60

    def seconds(self) -> int:
        return self._base_value // 1000**2

    def millis(self) -> int:
        return self._base_value // 1000

    def micros(self) -> int:
        return self._base_value


class EscapedStr(StrBase):
    """
    A string where escape sequences are ignored and quotes are escaped.
    """

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)

        escape = {
            "'": r"\'",
            '"': r"\"",
            "\a": r"\a",
            "\n": r"\n",
            "\r": r"\r",
            "\t": r"\t",
            "\b": r"\b",
            "\f": r"\f",
            "\v": r"\v",
            "\0": r"\0",
        }

        s = list(self._value)
        for i, c in enumerate(self._value):
            if c in escape:
                s[i] = escape[c]
            elif not c.isalnum():
                s[i] = repr(c)[1:-1]
        self._value = "".join(s)

    def multiline(self) -> str:
        """
        Lua multiline string is enclosed in double square brackets '[[ ]]'.
        This method makes sure that double square brackets are escaped.
        """

        replace = {
            "[[": r"\[\[",
            "]]": r"\]\]",
        }

        ml = self._orig_value
        for s, r in replace.items():
            ml = ml.replace(s, r)
        return ml


class EscapedStr32B(EscapedStr, StringLengthBase):
    """
    Same as 'EscapedStr', but minimal length is 32 bytes.
    """

    _min_bytes: int = 32


class DomainName(StrBase):
    """
    Fully or partially qualified domain name.
    """

    _punycode: str
    _re = re.compile(
        r"(?=^.{,253}\.?$)"  # max 253 chars
        r"(^(?!\.)"  # do not start name with dot
        r"((?!-)"  # do not start label with hyphen
        r"\.?[a-zA-Z0-9-]{,62}"  # max 63 chars in label
        r"[a-zA-Z0-9])+"  # do not end label with hyphen
        r"\.?$)"  # end with or without '.'
        r"|^\.$"  # allow root-zone
    )

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        try:
            punycode = self._value.encode("idna").decode("utf-8") if self._value != "." else "."
        except ValueError as e:
            raise ValueError(
                f"conversion of '{self._value}' to IDN punycode representation failed",
                object_path,
            ) from e

        if type(self)._re.match(punycode):  # noqa: SLF001
            self._punycode = punycode
        else:
            raise ValueError(
                f"'{source_value}' represented in punycode '{punycode}' does not match '{self._re.pattern}' pattern",
                object_path,
            )

    def __hash__(self) -> int:
        if self._value.endswith("."):
            return hash(self._value)
        return hash(f"{self._value}.")

    def punycode(self) -> str:
        return self._punycode

    @classmethod
    def json_schema(cls: Type["DomainName"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}


class InterfaceName(PatternBase):
    """
    Network interface name.
    """

    _re = re.compile(r"^[a-zA-Z0-9]+(?:[-_][a-zA-Z0-9]+)*$")


class IDPattern(PatternBase):
    """
    Alphanumerical ID for identifying systemd slice.
    """

    _re = re.compile(r"^(?!-)[a-z0-9-]*[a-z0-9]+$")


class PinSha256(PatternBase):
    """
    A string that stores base64 encoded sha256.
    """

    _re = re.compile(r"^[A-Za-z\d+/]{43}=$")


class InterfacePort(StrBase):
    addr: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address] = None
    if_name: Optional[InterfaceName] = None
    port: PortNumber

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)

        parts = self._value.split("@")
        if len(parts) == 2:
            try:
                self.addr = ipaddress.ip_address(parts[0])
            except ValueError as e1:
                try:
                    self.if_name = InterfaceName(parts[0])
                except ValueError as e2:
                    raise ValueError(f"expected IP address or interface name, got '{parts[0]}'.", object_path) from (
                        e1 and e2
                    )
            self.port = PortNumber.from_str(parts[1], object_path)
        else:
            raise ValueError(f"expected '<ip-address|interface-name>@<port>', got '{source_value}'.", object_path)


class InterfaceOptionalPort(StrBase):
    addr: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address] = None
    if_name: Optional[InterfaceName] = None
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)

        parts = self._value.split("@")
        if 0 < len(parts) < 3:
            try:
                self.addr = ipaddress.ip_address(parts[0])
            except ValueError as e1:
                try:
                    self.if_name = InterfaceName(parts[0])
                except ValueError as e2:
                    raise ValueError(f"expected IP address or interface name, got '{parts[0]}'.", object_path) from (
                        e1 and e2
                    )
            if len(parts) == 2:
                self.port = PortNumber.from_str(parts[1], object_path)
        else:
            raise ValueError(f"expected '<ip-address|interface-name>[@<port>]', got '{parts}'.", object_path)


class IPAddressPort(StrBase):
    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: PortNumber

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)

        parts = self._value.split("@")
        if len(parts) == 2:
            self.port = PortNumber.from_str(parts[1], object_path)
            try:
                self.addr = ipaddress.ip_address(parts[0])
            except ValueError as e:
                raise ValueError(f"failed to parse IP address '{parts[0]}'.", object_path) from e
        else:
            raise ValueError(f"expected '<ip-address>@<port>', got '{source_value}'.", object_path)


class IPAddressOptionalPort(StrBase):
    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        parts = source_value.split("@")
        if 0 < len(parts) < 3:
            try:
                self.addr = ipaddress.ip_address(parts[0])
            except ValueError as e:
                raise ValueError(f"failed to parse IP address '{parts[0]}'.", object_path) from e
            if len(parts) == 2:
                self.port = PortNumber.from_str(parts[1], object_path)
        else:
            raise ValueError(f"expected '<ip-address>[@<port>]', got '{parts}'.", object_path)


class IPv4Address(BaseValueType):
    _value: ipaddress.IPv4Address

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv4Address = ipaddress.IPv4Address(source_value)
            except ValueError as e:
                raise ValueError("failed to parse IPv4 address.") from e
        else:
            raise ValueError(
                "Unexpected value for a IPv4 address."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def to_std(self) -> ipaddress.IPv4Address:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __int__(self) -> int:
        raise ValueError("Can't convert IPv4 address to an integer")

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        """
        Two instances of IPv4Address are equal when they represent same IPv4 address as string.
        """
        return isinstance(o, IPv4Address) and str(o._value) == str(self._value)

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["IPv4Address"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPv6Address(BaseValueType):
    _value: ipaddress.IPv6Address

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv6Address = ipaddress.IPv6Address(source_value)
            except ValueError as e:
                raise ValueError("failed to parse IPv6 address.") from e
        else:
            raise ValueError(
                "Unexpected value for a IPv6 address."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def to_std(self) -> ipaddress.IPv6Address:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __int__(self) -> int:
        raise ValueError("Can't convert IPv6 address to an integer")

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        """
        Two instances of IPv6Address are equal when they represent same IPv6 address as string.
        """
        return isinstance(o, IPv6Address) and str(o._value) == str(self._value)

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["IPv6Address"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


IPAddress = Union[IPv4Address, IPv6Address]


class IPAddressEM(BaseValueType):
    """
    IP address with exclamation mark suffix, e.g. '127.0.0.1!'.
    """

    _value: str
    _addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, str):
            if source_value.endswith("!"):
                addr, suff = source_value.split("!", 1)
                if suff != "":
                    raise ValueError(f"suffix '{suff}' found after '!'.")
            else:
                raise ValueError("string does not end with '!'.")
            try:
                self._addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = ipaddress.ip_address(addr)
                self._value = source_value
            except ValueError as e:
                raise ValueError("failed to parse IP address.") from e
        else:
            raise ValueError(
                "Unexpected value for a IPv6 address."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def to_std(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __int__(self) -> int:
        raise ValueError("Can't convert to an integer")

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        """
        Two instances of IPAddressEM are equal when they represent same string.
        """
        return isinstance(o, IPAddressEM) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["IPAddressEM"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPNetwork(BaseValueType):
    _value: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, str):
            try:
                self._value: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(source_value)
            except ValueError as e:
                raise ValueError("failed to parse IP network.") from e
        else:
            raise ValueError(
                "Unexpected value for a network subnet."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'"
            )

    def __int__(self) -> int:
        raise ValueError("Can't convert network prefix to an integer")

    def __str__(self) -> str:
        return self._value.with_prefixlen

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IPNetwork) and o._value == self._value

    def to_std(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        return self._value

    def serialize(self) -> Any:
        return self._value.with_prefixlen

    @classmethod
    def json_schema(cls: Type["IPNetwork"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPv6Network(BaseValueType):
    _value: ipaddress.IPv6Network

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv6Network = ipaddress.IPv6Network(source_value)
            except ValueError as e:
                raise ValueError("failed to parse IPv6 network.") from e
        else:
            raise ValueError(
                "Unexpected value for a IPv6 network subnet."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'"
            )

    def to_std(self) -> ipaddress.IPv6Network:
        return self._value

    def __str__(self) -> str:
        return self._value.with_prefixlen

    def __int__(self) -> int:
        raise ValueError("Can't convert network prefix to an integer")

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IPv6Network) and o._value == self._value

    def serialize(self) -> Any:
        return self._value.with_prefixlen

    @classmethod
    def json_schema(cls: Type["IPv6Network"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPv6Network96(IPv6Network):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        if self._value.prefixlen == 128:
            raise ValueError(
                "Expected IPv6 network address with /96 prefix length."
                " Submitted address has been interpreted as /128."
                " Maybe, you forgot to add /96 after the base address?"
            )

        if self._value.prefixlen != 96:
            raise ValueError(
                "expected IPv6 network address with /96 prefix length." f" Got prefix lenght of {self._value.prefixlen}"
            )
