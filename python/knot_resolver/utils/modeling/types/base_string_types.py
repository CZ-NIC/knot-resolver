from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from knot_resolver.utils.modeling.errors import DataTypeError, DataValueError

from .base_types import BaseType

if TYPE_CHECKING:
    from re import Pattern


class BaseString(BaseType):
    """Base class to work with string value."""

    def validate(self) -> None:
        if not isinstance(self._value, (str, int)) or isinstance(self._value, bool):
            msg = (
                f"Unexpected value for '{type(self)}'."
                f" Expected string, got '{self._value}' with type '{type(self._value)}'"
            )
            raise DataTypeError(msg, self._tree_path)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "string"}


class BaseStringLength(BaseString):
    _min_bytes: int = 1
    _max_bytes: int

    def validate(self) -> None:
        super().validate()
        value_bytes = len(self._value.encode("utf-8"))
        if hasattr(self, "_min_bytes") and (value_bytes < self._min_bytes):
            msg = f"the string value {self._value} is shorter than the minimum {self._min_bytes} bytes."
            raise DataValueError(msg, self._tree_path)
        if hasattr(self, "_max_bytes") and (value_bytes > self._max_bytes):
            msg = f"the string value {self._value} is longer than the maximum {self._max_bytes} bytes."
            raise DataValueError(msg, self._tree_path)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        typ: dict[str, Any] = {"type": "string"}
        if hasattr(cls, "_min_bytes"):
            typ["minLength"] = cls._min_bytes
        if hasattr(cls, "_max_bytes"):
            typ["maxLength"] = cls._max_bytes
        return typ


class BaseStringPattern(BaseString):
    _re: Pattern[str]

    def validate(self) -> None:
        super().validate()
        if not type(self)._re.match(self._value):  # noqa: SLF001
            msg = f"'{self._value}' does not match '{self._re.pattern}' pattern"
            raise DataValueError(msg, self._tree_path)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}


class BaseUnit(BaseString):
    _re: Pattern[str]
    _units: dict[str, int]

    def __init__(self, value: Any, tree_path: str = "/", base_path: Path = Path()) -> None:
        super().__init__(value, tree_path, base_path)
        type(self)._re = re.compile(rf"^(\d+)({r'|'.join(type(self)._units.keys())})$")  # noqa: SLF001

    def _get_base_value(self) -> float:
        cls = self.__class__

        super().validate()
        if isinstance(self._value, int) and not isinstance(self._value, bool):
            return self._value

        grouped = self._re.search(self._value)
        if grouped:
            val, unit = grouped.groups()
            if unit is None:
                msg = f"Missing units. Accepted units are {list(cls._units.keys())}"
                raise DataValueError(msg, self._tree_path)
            if unit not in cls._units:
                msg = (
                    f"Used unexpected unit '{unit}' for {type(self).__name__}."
                    f" Accepted units are {list(cls._units.keys())}"
                )
                raise DataValueError(msg, self._tree_path)
            return float(val) * cls._units[unit]
        msg = (
            f"Unexpected value for '{type(self)}'."
            " Expected string that matches pattern "
            rf"'{type(self)._re.pattern}'."  # noqa: SLF001
            f" Positive integer and one of the units {list(type(self)._units.keys())}, got '{self._value}'."  # noqa: SLF001
        )
        raise DataValueError(msg, self._tree_path)

    def validate(self) -> None:
        self._get_base_value()

    def __int__(self) -> int:
        return int(self._get_base_value())

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}
