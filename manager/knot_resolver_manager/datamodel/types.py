import ipaddress
import logging
import os
import re
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Optional, Pattern, Type, Union

from typing_extensions import Literal

from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils import CustomValueType, SchemaNode
from knot_resolver_manager.utils.modelling import Serializable

logger = logging.getLogger(__name__)

# Policy actions
ActionEnum = Literal[
    # Nonchain actions
    "pass",
    "deny",
    "drop",
    "refuse",
    "tc",
    "reroute",
    "answer",
    # Chain actions
    "mirror",
    "debug-always",
    "debug-cache-miss",
    "qtrace",
    "reqtrace",
]

# FLAGS from https://knot-resolver.readthedocs.io/en/stable/lib.html?highlight=options#c.kr_qflags
FlagsEnum = Literal[
    "no-minimize",
    "no-ipv4",
    "no-ipv6",
    "tcp",
    "resolved",
    "await-ipv4",
    "await-ipv6",
    "await-cut",
    "no-edns",
    "cached",
    "no-cache",
    "expiring",
    "allow_local",
    "dnssec-want",
    "dnssec-bogus",
    "dnssec-insecure",
    "dnssec-cd",
    "stub",
    "always-cut",
    "dnssec-wexpand",
    "permissive",
    "strict",
    "badcookie-again",
    "cname",
    "reorder-rr",
    "trace",
    "no-0x20",
    "dnssec-nods",
    "dnssec-optout",
    "nonauth",
    "forward",
    "dns64-mark",
    "cache-tried",
    "no-ns-found",
    "pkt-is-sane",
    "dns64-disable",
]

# DNS record types from 'kres.type' table
RecordTypeEnum = Literal[
    "A",
    "A6",
    "AAAA",
    "AFSDB",
    "ANY",
    "APL",
    "ATMA",
    "AVC",
    "AXFR",
    "CAA",
    "CDNSKEY",
    "CDS",
    "CERT",
    "CNAME",
    "CSYNC",
    "DHCID",
    "DLV",
    "DNAME",
    "DNSKEY",
    "DOA",
    "DS",
    "EID",
    "EUI48",
    "EUI64",
    "GID",
    "GPOS",
    "HINFO",
    "HIP",
    "HTTPS",
    "IPSECKEY",
    "ISDN",
    "IXFR",
    "KEY",
    "KX",
    "L32",
    "L64",
    "LOC",
    "LP",
    "MAILA",
    "MAILB",
    "MB",
    "MD",
    "MF",
    "MG",
    "MINFO",
    "MR",
    "MX",
    "NAPTR",
    "NID",
    "NIMLOC",
    "NINFO",
    "NS",
    "NSAP",
    "NSAP-PTR",
    "NSEC",
    "NSEC3",
    "NSEC3PARAM",
    "NULL",
    "NXT",
    "OPENPGPKEY",
    "OPT",
    "PTR",
    "PX",
    "RKEY",
    "RP",
    "RRSIG",
    "RT",
    "SIG",
    "SINK",
    "SMIMEA",
    "SOA",
    "SPF",
    "SRV",
    "SSHFP",
    "SVCB",
    "TA",
    "TALINK",
    "TKEY",
    "TLSA",
    "TSIG",
    "TXT",
    "UID",
    "UINFO",
    "UNSPEC",
    "URI",
    "WKS",
    "X25",
    "ZONEMD",
]


class IntRange(CustomValueType):
    _value: int
    _min: int
    _max: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, int):
            if not self._min <= source_value <= self._max:
                raise SchemaException(
                    f"Integer value {source_value} out of range <{self._min}, {self._max}>", object_path
                )
            self._value = source_value
        else:
            raise SchemaException(
                f"Unexpected input type for integer - {type(source_value)}."
                " Cause might be invalid format or invalid type.",
                object_path,
            )

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IntRange) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["IntRange"]) -> Dict[Any, Any]:
        return {"type": "integer", "minimum": cls._min, "maximum": cls._max}


class PortNumber(IntRange):
    _min: int = 1
    _max: int = 65_535


class Unit(CustomValueType):
    _re: Pattern[str]
    _units: Dict[str, int]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        self._value: int
        self._value_orig: Union[str, int]
        if isinstance(source_value, str) and type(self)._re.match(source_value):
            self._value_orig = source_value
            grouped = type(self)._re.search(source_value)
            if grouped:
                val, unit = grouped.groups()
                if unit is None:
                    raise SchemaException(
                        f"Missing units. Accepted units are {list(type(self)._units.keys())}", object_path
                    )
                elif unit not in type(self)._units:
                    raise SchemaException(
                        f"Used unexpected unit '{unit}' for {type(self).__name__}."
                        f" Accepted units are {list(type(self)._units.keys())}",
                        object_path,
                    )
                self._value = int(val) * type(self)._units[unit]
            else:
                raise SchemaException(f"{type(self._value)} Failed to convert: {self}", object_path)
        elif isinstance(source_value, int):
            raise SchemaException(
                "We do not accept number without units."
                f" Please convert the value to string an add a unit - {list(type(self)._units.keys())}",
                object_path,
            )
        else:
            raise SchemaException(
                f"Unexpected input type for Unit type - {type(source_value)}."
                " Cause might be invalid format or invalid type.",
                object_path,
            )

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        """
        Used by Jinja2. Must return only a number.
        """
        return str(self._value_orig)

    def __repr__(self) -> str:
        return f"Unit[{type(self).__name__},{self._value_orig}]"

    def __eq__(self, o: object) -> bool:
        """
        Two instances are equal when they represent the same size
        regardless of their string representation.
        """
        return isinstance(o, Unit) and o._value == self._value

    def serialize(self) -> Any:
        return self._value_orig

    @classmethod
    def json_schema(cls: Type["Unit"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": r"\d+(" + "|".join(cls._units.keys()) + ")"}


class SizeUnit(Unit):
    _re = re.compile(r"^([0-9]+)\s{0,1}([BKMG]){0,1}$")
    _units = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}

    def bytes(self) -> int:
        return self._value


class TimeUnit(Unit):
    _re = re.compile(r"^(\d+)\s{0,1}([smhd]s?){0,1}$")
    _units = {"ms": 1, "s": 1000, "m": 60 * 1000, "h": 3600 * 1000, "d": 24 * 3600 * 1000}

    def seconds(self) -> int:
        return self._value // 1000

    def millis(self) -> int:
        return self._value


class UncheckedPath(CustomValueType):
    """
    Wrapper around pathlib.Path object. Can represent pretty much any Path. No checks are
    performed on the value. The value is taken as is.
    """

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        if isinstance(source_value, str):
            self._value: Path = Path(source_value)
        else:
            raise SchemaException(
                f"Expected file path in a string, got '{source_value}' with type '{type(source_value)}'", object_path
            )

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
            raise SchemaException("Failed to resolve given file path. Is there a symlink loop?", object_path) from e


class DomainName(CustomValueType):
    _re = re.compile(
        r"^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|"
        r"([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|"
        r"([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\."
        r"([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})($|.$)"
    )

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            if type(self)._re.match(source_value):
                self._value: str = source_value
            else:
                raise SchemaException(f"'{source_value}' is not valid domain name", object_path)
        else:
            raise SchemaException(
                f"Unexpected input type for DomainName type - {type(source_value)}."
                "Cause might be invalid format or invalid type.",
                object_path,
            )

    def to_std(self) -> str:
        return self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __str__(self) -> str:
        return self._value

    def __int__(self) -> int:
        raise ValueError("Can't convert DomainName to an integer")

    def __eq__(self, o: object) -> bool:
        """
        Two instances of DomainName are equal when they represent same string.
        """
        return isinstance(o, DomainName) and str(o._value) == str(self._value)

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["DomainName"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class InterfacePort(CustomValueType):
    intrfc: str
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            if "@" in source_value:
                sep = source_value.split("@", 1)
                try:
                    self.port = PortNumber(int(sep[1]))
                except ValueError as e:
                    raise SchemaException("Failed to parse port.", object_path) from e
                self.intrfc = sep[0]
            else:
                self.intrfc = source_value
            self._value = source_value

        else:
            raise SchemaException(
                f"Unexpected value for a '<interface>[@<port>]'. Expected string, got '{source_value}'"
                f" with type '{type(source_value)}'",
                object_path,
            )

    def to_std(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __int__(self) -> int:
        raise ValueError("Can't convert InterfacePort to an integer")

    def __eq__(self, o: object) -> bool:
        """
        Two instances of InterfacePort are equal when they represent same string.
        """
        return isinstance(o, InterfacePort) and str(o._value) == str(self._value)

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["InterfacePort"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPAddressPort(CustomValueType):
    addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: Optional[PortNumber] = None

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            if "@" in source_value:
                sep = source_value.split("@", 1)
                try:
                    self.port = PortNumber(int(sep[1]))
                except ValueError as e:
                    raise SchemaException("Failed to parse port.", object_path) from e

                try:
                    self.addr = ipaddress.ip_address(sep[0])
                except ValueError as e:
                    raise SchemaException("Failed to parse IP address.", object_path) from e
            else:
                try:
                    self.addr = ipaddress.ip_address(source_value)
                except ValueError as e:
                    raise SchemaException("Failed to parse IP address.", object_path) from e
            self._value = source_value

        else:
            raise SchemaException(
                f"Unexpected value for a '<ip-address>[@<port>]'. Expected string, got '{source_value}'"
                f" with type '{type(source_value)}'",
                object_path,
            )

    def to_std(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __int__(self) -> int:
        raise ValueError("Can't convert IP address to an integer")

    def __eq__(self, o: object) -> bool:
        """
        Two instances of IPAddressPORT are equal when they represent same string.
        """
        return isinstance(o, IPAddressPort) and str(o._value) == str(self._value)

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["IPAddressPort"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class IPv4Address(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv4Address = ipaddress.IPv4Address(source_value)
            except ValueError as e:
                raise SchemaException("Failed to parse IPv4 address.", object_path) from e
        else:
            raise SchemaException(
                f"Unexpected value for a IPv4 address. Expected string, got '{source_value}'"
                f" with type '{type(source_value)}'",
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


class IPv6Address(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv6Address = ipaddress.IPv6Address(source_value)
            except ValueError as e:
                raise SchemaException("Failed to parse IPv6 address.", object_path) from e
        else:
            raise SchemaException(
                f"Unexpected value for a IPv6 address. Expected string, got '{source_value}'"
                f" with type '{type(source_value)}'",
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


class IPNetwork(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            try:
                self._value: Union[ipaddress.IPv4Network, ipaddress.IPv6Network] = ipaddress.ip_network(source_value)
            except ValueError as e:
                raise SchemaException("Failed to parse IP network.", object_path) from e
        else:
            raise SchemaException(
                f"Unexpected value for a network subnet. Expected string, got '{source_value}'"
                " with type '{type(source_value)}'",
                object_path,
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


class IPv6Network96(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path=object_path)
        if isinstance(source_value, str):
            try:
                self._value: ipaddress.IPv6Network = ipaddress.IPv6Network(source_value)
            except ValueError as e:
                raise SchemaException("Failed to parse IPv6 /96 network.", object_path) from e

            if self._value.prefixlen == 128:
                raise SchemaException(
                    "Expected IPv6 network address with /96 prefix length."
                    " Submitted address has been interpreted as /128."
                    " Maybe, you forgot to add /96 after the base address?",
                    object_path,
                )

            if self._value.prefixlen != 96:
                raise SchemaException(
                    "Expected IPv6 network address with /96 prefix length."
                    f" Got prefix lenght of {self._value.prefixlen}",
                    object_path,
                )
        else:
            raise SchemaException(
                "Unexpected value for a network subnet."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
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


class ListenType(Enum):
    IP = auto()
    UNIX_SOCKET = auto()
    INTERFACE = auto()


class Listen(SchemaNode, Serializable):
    class Raw(SchemaNode):
        ip: Optional[IPAddress] = None
        port: Optional[int] = None
        unix_socket: Optional[CheckedPath] = None
        interface: Optional[str] = None

    _PREVIOUS_SCHEMA = Raw

    typ: ListenType
    ip: Optional[IPAddress]
    port: Optional[int]
    unix_socket: Optional[CheckedPath]
    interface: Optional[str]

    def _typ(self, origin: Raw) -> ListenType:
        present = {
            "ip" if origin.ip is not None else ...,
            "port" if origin.port is not None else ...,
            "unix_socket" if origin.unix_socket is not None else ...,
            "interface" if origin.interface is not None else ...,
        }

        if present == {"ip", ...} or present == {"ip", "port", ...}:
            return ListenType.IP
        elif present == {"unix_socket", ...}:
            return ListenType.UNIX_SOCKET
        elif present == {"interface", ...} or present == {"interface", "port", ...}:
            return ListenType.INTERFACE
        else:
            raise ValueError(
                "Listen configuration contains multiple incompatible options at once. "
                "You can use (IP and PORT) or (UNIX_SOCKET) or (INTERFACE and PORT)."
            )

    def _port(self, origin: Raw) -> Optional[int]:
        if origin.port is None:
            return None
        if not 0 <= origin.port <= 65_535:
            raise ValueError(f"Port value {origin.port} out of range of usual 2-byte port value")
        return origin.port

    def _validate(self) -> None:
        # we already check that it's there is only one option in the `_typ` method
        pass

    def __str__(self) -> str:
        if self.typ is ListenType.IP:
            return f"{self.ip} @ {self.port}"
        elif self.typ is ListenType.UNIX_SOCKET:
            return f"{self.unix_socket}"
        elif self.typ is ListenType.INTERFACE:
            return f"{self.interface} @ {self.port}"
        else:
            raise NotImplementedError()

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, Listen):
            return False

        return (
            self.port == o.port
            and self.ip == o.ip
            and self.typ == o.typ
            and self.unix_socket == o.unix_socket
            and self.interface == o.interface
        )

    def to_dict(self) -> Dict[Any, Any]:
        if self.typ is ListenType.IP:
            return {"port": self.port, "ip": str(self.ip)}
        elif self.typ is ListenType.UNIX_SOCKET:
            return {"unix_socket": str(self.unix_socket)}
        elif self.typ is ListenType.INTERFACE:
            return {"interface": self.interface, "port": self.port}
        else:
            raise NotImplementedError()
