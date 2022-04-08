import ipaddress
import logging
import re
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Optional, Pattern, Type, Union

from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils import CustomValueType, SchemaNode

logger = logging.getLogger(__name__)


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


class AnyPath(CustomValueType):
    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            self._value: Path = Path(source_value)
        else:
            raise SchemaException(
                f"Expected file path in a string, got '{source_value}' with type '{type(source_value)}'", object_path
            )

        try:
            self._value = self._value.resolve(strict=False)
        except RuntimeError as e:
            raise SchemaException("Failed to resolve given file path. Is there a symlink loop?", object_path) from e

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, _o: object) -> bool:
        raise RuntimeError("Path's cannot be simply compared for equality")

    def __int__(self) -> int:
        raise RuntimeError("Path cannot be converted to type <int>")

    def to_path(self) -> Path:
        return self._value

    def serialize(self) -> Any:
        return str(self._value)

    @classmethod
    def json_schema(cls: Type["AnyPath"]) -> Dict[Any, Any]:
        return {
            "type": "string",
        }


class ListenType(Enum):
    IP_AND_PORT = auto()
    UNIX_SOCKET = auto()
    INTERFACE_AND_PORT = auto()


class Listen(SchemaNode):
    class Raw(SchemaNode):
        ip: Optional[str] = None
        port: Optional[int] = None
        unix_socket: Optional[AnyPath] = None
        interface: Optional[str] = None

    _PREVIOUS_SCHEMA = Raw

    typ: ListenType
    ip: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]
    port: Optional[int]
    unix_socket: Optional[AnyPath]
    interface: Optional[str]

    def _typ(self, origin: Raw):
        present = {
            "ip" if origin.ip is not None else ...,
            "port" if origin.port is not None else ...,
            "unix_socket" if origin.unix_socket is not None else ...,
            "interface" if origin.interface is not None else ...,
        }

        if present == {"ip", "port", ...}:
            return ListenType.IP_AND_PORT
        elif present == {"unix_socket", ...}:
            return ListenType.UNIX_SOCKET
        elif present == {"interface", "port", ...}:
            return ListenType.INTERFACE_AND_PORT
        else:
            raise ValueError(
                "Listen configuration contains multiple incompatible options at once. "
                "You can use (IP and PORT) or (UNIX_SOCKET) or (INTERFACE and PORT)."
            )

    def _port(self, origin: Raw):
        if origin.port is None:
            return None
        if not 0 <= origin.port <= 65_535:
            raise ValueError(f"Port value {origin.port} out of range of usual 2-byte port value")
        return origin.port

    def _ip(self, origin: Raw):
        if origin.ip is None:
            return None
        # throws value error, so that get's caught outside of this function
        return ipaddress.ip_address(origin.ip)

    def _validate(self) -> None:
        # we already check that it's there is only one option in the `_typ` method
        pass

    def __str__(self) -> str:
        if self.typ is ListenType.IP_AND_PORT:
            return f"{self.ip} @ {self.port}"
        elif self.typ is ListenType.UNIX_SOCKET:
            return f"{self.unix_socket}"
        elif self.typ is ListenType.INTERFACE_AND_PORT:
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
