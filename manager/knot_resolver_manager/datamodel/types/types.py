import ipaddress
import re
from pathlib import Path
from typing import Any, Dict, Optional, Type, Union

from knot_resolver_manager.datamodel.types.base_types import IntRangeBase, PatternBase, StrBase, UnitBase
from knot_resolver_manager.utils.modeling import BaseCustomType


class IntNonNegative(IntRangeBase):
    _min: int = 0


class IntPositive(IntRangeBase):
    _min: int = 1


class Int0_512(IntRangeBase):
    _min: int = 0
    _max: int = 512


class Int0_65535(IntRangeBase):
    _min: int = 0
    _max: int = 65_535


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
    _units = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}

    def bytes(self) -> int:
        return self._value


class TimeUnit(UnitBase):
    _units = {"ms": 1, "s": 1000, "m": 60 * 1000, "h": 3600 * 1000, "d": 24 * 3600 * 1000}

    def seconds(self) -> int:
        return self._value // 1000

    def millis(self) -> int:
        return self._value


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
        super().__init__(source_value)
        if isinstance(source_value, str):
            try:
                punycode = source_value.encode("idna").decode("utf-8") if source_value != "." else "."
            except ValueError:
                raise ValueError(
                    f"conversion of '{source_value}' to IDN punycode representation failed",
                    object_path,
                )

            if type(self)._re.match(punycode):
                self._value = source_value
                self._punycode = punycode
            else:
                raise ValueError(
                    f"'{source_value}' represented in punycode '{punycode}' does not match '{self._re.pattern}' pattern",
                    object_path,
                )
        else:
            raise ValueError(
                "Unexpected value for '<domain-name>'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
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
    _re = re.compile(r"^[a-zA-Z0-9]+(?:[-_][a-zA-Z0-9]+)*$")


class IDPattern(PatternBase):
    """
    Alphanumerical ID for identifying systemd slice.
    """

    _re = re.compile(r"[a-zA-Z0-9]+")


class InterfacePort(StrBase):
    addr: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address] = None
    if_name: Optional[InterfaceName] = None
    port: PortNumber

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            parts = source_value.split("@")
            if len(parts) == 2:
                try:
                    self.addr = ipaddress.ip_address(parts[0])
                except ValueError as e1:
                    try:
                        self.if_name = InterfaceName(parts[0])
                    except ValueError as e2:
                        raise ValueError(f"expected IP address or interface name, got '{parts[0]}'.") from e1 and e2
                self.port = PortNumber.from_str(parts[1], object_path)
            else:
                raise ValueError(f"expected '<ip-address|interface-name>@<port>', got '{source_value}'.")
            self._value = source_value
        else:
            raise ValueError(
                "Unexpected value for '<ip-address|interface-name>@<port>'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )


class InterfaceOptionalPort(StrBase):
    addr: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address] = None
    if_name: Optional[InterfaceName] = None
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            parts = source_value.split("@")
            if 0 < len(parts) < 3:
                try:
                    self.addr = ipaddress.ip_address(parts[0])
                except ValueError as e1:
                    try:
                        self.if_name = InterfaceName(parts[0])
                    except ValueError as e2:
                        raise ValueError(f"expected IP address or interface name, got '{parts[0]}'.") from e1 and e2
                if len(parts) == 2:
                    self.port = PortNumber.from_str(parts[1], object_path)
            else:
                raise ValueError(f"expected '<ip-address|interface-name>[@<port>]', got '{parts}'.")
            self._value = source_value
        else:
            raise ValueError(
                "Unexpected value for '<ip-address|interface-name>[@<port>]'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )


class IPAddressPort(StrBase):
    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: PortNumber

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            parts = source_value.split("@")
            if len(parts) == 2:
                self.port = PortNumber.from_str(parts[1], object_path)
                try:
                    self.addr = ipaddress.ip_address(parts[0])
                except ValueError as e:
                    raise ValueError(f"failed to parse IP address '{parts[0]}'.") from e
            else:
                raise ValueError(f"expected '<ip-address>@<port>', got '{source_value}'.")
            self._value = source_value
        else:
            raise ValueError(
                "Unexpected value for '<ip-address>@<port>'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'"
            )


class IPAddressOptionalPort(StrBase):
    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            parts = source_value.split("@")
            if 0 < len(parts) < 3:
                try:
                    self.addr = ipaddress.ip_address(parts[0])
                except ValueError as e:
                    raise ValueError(f"failed to parse IP address '{parts[0]}'.") from e
                if len(parts) == 2:
                    self.port = PortNumber.from_str(parts[1], object_path)
            else:
                raise ValueError(f"expected '<ip-address>[@<port>]', got '{parts}'.")
            self._value = source_value
        else:
            raise ValueError(
                "Unexpected value for a '<ip-address>[@<port>]'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )


class IPv4Address(BaseCustomType):
    _value: ipaddress.IPv4Address

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
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


class IPv6Address(BaseCustomType):
    _value: ipaddress.IPv6Address

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
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


class IPNetwork(BaseCustomType):
    _value: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
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

    def to_std(self) -> Union[ipaddress.IPv4Network, ipaddress.IPv6Network]:
        return self._value

    def __str__(self) -> str:
        return self._value.with_prefixlen

    def __int__(self) -> int:
        raise ValueError("Can't convert network prefix to an integer")

    def serialize(self) -> Any:
        return self._value.with_prefixlen

    @classmethod
    def json_schema(cls: Type["IPNetwork"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPv6Network96(BaseCustomType):
    _value: ipaddress.IPv6Network

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv6Network = ipaddress.IPv6Network(source_value)
            except ValueError as e:
                raise ValueError("failed to parse IPv6 /96 network.") from e

            if self._value.prefixlen == 128:
                raise ValueError(
                    "Expected IPv6 network address with /96 prefix length."
                    " Submitted address has been interpreted as /128."
                    " Maybe, you forgot to add /96 after the base address?"
                )

            if self._value.prefixlen != 96:
                raise ValueError(
                    "expected IPv6 network address with /96 prefix length."
                    f" Got prefix lenght of {self._value.prefixlen}"
                )
        else:
            raise ValueError(
                "Unexpected value for a network subnet."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'"
            )

    def __str__(self) -> str:
        return self._value.with_prefixlen

    def __int__(self) -> int:
        raise ValueError("Can't convert network prefix to an integer")

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IPv6Network96) and o._value == self._value

    def serialize(self) -> Any:
        return self._value.with_prefixlen

    def to_std(self) -> ipaddress.IPv6Network:
        return self._value

    @classmethod
    def json_schema(cls: Type["IPv6Network96"]) -> Dict[Any, Any]:
        return {"type": "string"}


class UncheckedPath(BaseCustomType):
    """
    Wrapper around pathlib.Path object. Can represent pretty much any Path. No checks are
    performed on the value. The value is taken as is.
    """

    _value: Path

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        if isinstance(source_value, str):
            self._value: Path = Path(source_value)
        else:
            raise ValueError(f"expected file path in a string, got '{source_value}' with type '{type(source_value)}'.")

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, UncheckedPath):
            return False

        return o._value == self._value

    def __int__(self) -> int:
        raise RuntimeError("Path cannot be converted to type <int>")

    def to_path(self) -> Path:
        return self._value

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["UncheckedPath"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class CheckedPath(UncheckedPath):
    """
    Like UncheckedPath, but the file path is checked for being valid. So no non-existent directories in the middle,
    no symlink loops. This however means, that resolving of relative path happens while validating.
    """

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        try:
            self._value = self._value.resolve(strict=False)
        except RuntimeError as e:
            raise ValueError("Failed to resolve given file path. Is there a symlink loop?") from e
