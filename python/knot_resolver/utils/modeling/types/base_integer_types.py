from __future__ import annotations

from typing import TYPE_CHECKING, Any

from knot_resolver.utils.modeling.context import Strictness
from knot_resolver.utils.modeling.errors import DataTypeError, DataValueError

from .base_custom_type import BaseCustomType

if TYPE_CHECKING:
    from knot_resolver.utils.modeling.context import Context


class BaseInteger(BaseCustomType):
    """Base class to work with integer value."""

    def _validate(self, context: Context) -> None:
        if (
            context.strictness > Strictness.PERMISSIVE
            and not isinstance(self._value, int)
            or isinstance(self._value, bool)
        ):
            msg = (
                f"Unexpected value for '{type(self)}'"
                f" Expected integer, got '{self._value}' with type '{type(self._value)}'"
            )
            raise DataTypeError(msg, self._tree_path)

    def __int__(self) -> int:
        return int(self._value)

    @classmethod
    def from_string(cls, value: str, tree_path: str = "/") -> BaseInteger:
        try:
            return cls(int(value), tree_path)
        except ValueError as e:
            msg = f"invalid integer {value}"
            raise DataValueError(msg) from e

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "integer"}


class BaseIntegerRange(BaseInteger):
    _min: int
    _max: int

    def _validate(self, context: Context) -> None:
        super()._validate(context)
        if context.strictness > Strictness.PERMISSIVE and hasattr(self, "_min") and (self._value < self._min):
            msg = f"value {self._value} is lower than the minimum {self._min}."
            raise DataValueError(msg, self._tree_path)
        if context.strictness > Strictness.PERMISSIVE and hasattr(self, "_max") and (self._value > self._max):
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
