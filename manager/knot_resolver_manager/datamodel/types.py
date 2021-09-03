import re
from typing import Any, Dict, Optional, Pattern, Union

from knot_resolver_manager.utils import CustomValueType, DataValidationException


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
