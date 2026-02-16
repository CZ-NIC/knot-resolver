from __future__ import annotations

from typing import TYPE_CHECKING, Any

from knot_resolver.utils.modeling.context import Strictness
from knot_resolver.utils.modeling.errors import DataTypeError, DataValueError

from .base_custom_type import BaseCustomType

if TYPE_CHECKING:
    from knot_resolver.utils.modeling.context import Context


class BaseFloat(BaseCustomType):
    """Base class to work with float value."""

    def validate(self, context: Context) -> None:
        if (
            context.strictness > Strictness.PERMISSIVE
            and not isinstance(self._value, (float, int))
            or isinstance(self._value, bool)
        ):
            msg = (
                f"Unexpected value for '{type(self)}'."
                f" Expected float, got '{self._value}' with type '{type(self._value)}'"
            )
            raise DataTypeError(msg, self._tree_path)

    def __int__(self) -> int:
        return int(self._value)

    def __float__(self) -> float:
        return float(self._value)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        return {"type": "number"}


class BaseFloatRange(BaseFloat):
    _min: float
    _max: float

    def validate(self, context: Context) -> None:
        super().validate(context)
        if context.strictness > Strictness.PERMISSIVE and hasattr(self, "_min") and (self._value < self._min):
            msg = f"value {self._value} is lower than the minimum {self._min}."
            raise DataValueError(msg, self._tree_path)
        if context.strictness > Strictness.PERMISSIVE and hasattr(self, "_max") and (self._value > self._max):
            msg = f"value {self._value} is higher than the maximum {self._max}"
            raise DataValueError(msg, self._tree_path)

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        typ: dict[str, Any] = {"type": "number"}
        if hasattr(cls, "_min"):
            typ["minimum"] = cls._min
        if hasattr(cls, "_max"):
            typ["maximum"] = cls._max
        return typ
