import ipaddress
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional, Pattern, Union, cast

from knot_resolver_manager.utils import CustomValueType, DataValidationException
from knot_resolver_manager.utils.data_parser_validator import DataParser

logger = logging.getLogger(__name__)


class Unit(CustomValueType):
    _re: Pattern[str]
    _units: Dict[Optional[str], int]

    def __init__(self, source_value: Any) -> None:
        super().__init__(source_value)
        self._value: int
        self._value_orig: Union[str, int]
        if isinstance(source_value, str) and type(self)._re.match(source_value):
            self._value_orig = source_value
            grouped = type(self)._re.search(source_value)
            if grouped:
                val, unit = grouped.groups()
                if unit not in type(self)._units:
                    raise DataValidationException(f"Used unexpected unit '{unit}' for {type(self).__name__}...")
                self._value = int(val) * type(self)._units[unit]
            else:
                raise DataValidationException(f"{type(self._value)} Failed to convert: {self}")
        elif isinstance(source_value, int):
            if source_value < 0:
                raise DataValidationException(f"Input value '{source_value}' is not non-negative.")
            self._value_orig = source_value
            self._value = source_value
        else:
            raise DataValidationException(
                f"Unexpected input type for Unit type - {type(source_value)}."
                " Cause might be invalid format or invalid type."
            )

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        """
        Used by Jinja2. Must return only a number.
        """
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        """
        Two instances are equal when they represent the same size
        regardless of their string representation.
        """
        return isinstance(o, Unit) and o._value == self._value


class SizeUnit(Unit):
    _re = re.compile(r"^([0-9]+)\s{0,1}([BKMG]){0,1}$")
    _units = {None: 1, "B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}


class TimeUnit(Unit):
    _re = re.compile(r"^(\d+)\s{0,1}([smhd]){0,1}$")
    _units = {None: 1, "s": 1, "m": 60, "h": 3600, "d": 24 * 3600}


class AnyPath(CustomValueType):
    def __init__(self, source_value: Any) -> None:
        super().__init__(source_value)
        if not isinstance(source_value, str):
            raise DataValidationException(f"Expected file path in a string, got '{source_value}'")
        self._value: Path = Path(source_value)

        try:
            self._value = self._value.resolve(strict=False)
        except RuntimeError as e:
            raise DataValidationException("Failed to resolve given file path. Is there a symlink loop?") from e

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, _o: object) -> bool:
        raise RuntimeError("Path's cannot be simply compared for equality")

    def __int__(self) -> int:
        raise RuntimeError("Path cannot be converted to type <int>")

    def to_path(self) -> Path:
        return self._value


class _IPAndPortData(DataParser):
    ip: str
    port: int


class IPAndPort(CustomValueType):
    """
    IP and port. Supports two formats:
      1. string in the form of 'ip@port'
      2. object with string field 'ip' and numeric field 'port'
    """

    def __init__(self, source_value: Any) -> None:
        super().__init__(source_value)

        # parse values from object
        if isinstance(source_value, dict):
            obj = _IPAndPortData(cast(Dict[Any, Any], source_value))
            ip = obj.ip
            port = obj.port

        # parse values from string
        elif isinstance(source_value, str):
            if "@" not in source_value:
                raise DataValidationException("Expected ip and port in format 'ip@port'. Missing '@'")
            ip, port_str = source_value.split(maxsplit=1, sep="@")
            try:
                port = int(port_str)
            except ValueError:
                raise DataValidationException(f"Failed to parse port number from string '{port_str}'")
        else:
            raise DataValidationException(
                "Expected IP and port as an object or as a string 'ip@port'," f" got '{source_value}'"
            )

        # validate port value range
        if not (0 <= port <= 65_535):
            raise DataValidationException(f"Port value {port} out of range of usual 2-byte port value")

        try:
            self.ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address] = ipaddress.ip_address(ip)
        except ValueError as e:
            raise DataValidationException(f"Failed to parse IP address from string '{ip}'") from e
        self.port: int = port

    def __str__(self) -> str:
        """
        Returns value in 'ip@port' format
        """
        return f"{self.ip}@{self.port}"
