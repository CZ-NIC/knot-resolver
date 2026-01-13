from __future__ import annotations

from typing import Any

from knot_resolver.utils.modeling.errors import DataTypeError, DataValueError

from .base_types import BaseType


class BaseInteger(BaseType):
    """Base class to work with integer value."""

    def validate(self) -> None:
        if not isinstance(self._value, int) or isinstance(self._value, bool):
            msg = (
                f"Unexpected value for '{type(self)}'"
                f" Expected integer, got '{self._value}' with type '{type(self._value)}'"
            )
            raise DataTypeError(msg, self._tree_path)

    def __int__(self) -> int:
        return int(self._value)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "integer"}


class BaseIntegerRange(BaseInteger):
    _min: int
    _max: int

    def validate(self) -> None:
        super().validate()
        if hasattr(self, "_min") and (self._value < self._min):
            msg = f"value {self._value} is lower than the minimum {self._min}."
            raise DataValueError(msg, self._tree_path)
        if hasattr(self, "_max") and (self._value > self._max):
            msg = f"value {self._value} is higher than the maximum {self._max}"
            raise DataValueError(msg, self._tree_path)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        typ: dict[str, Any] = {"type": "integer"}
        if hasattr(cls, "_min"):
            typ["minimum"] = cls._min
        if hasattr(cls, "_max"):
            typ["maximum"] = cls._max
        return typ
