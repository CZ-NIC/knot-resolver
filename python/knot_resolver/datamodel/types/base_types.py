# ruff: noqa: SLF001

import re
from typing import Any, Dict, Type, Union

from knot_resolver.utils.compat.typing import Pattern
from knot_resolver.utils.modeling import BaseValueType


class IntBase(BaseValueType):
    """Base class to work with integer value."""

    _orig_value: int
    _value: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, int) and not isinstance(source_value, bool):
            self._orig_value = source_value
            self._value = source_value
        else:
            raise ValueError(
                f"Unexpected value for '{type(self)}'."
                f" Expected integer, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IntBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._orig_value

    @classmethod
    def json_schema(cls: Type["IntBase"]) -> Dict[Any, Any]:
        return {"type": "integer"}


class FloatBase(BaseValueType):
    """Base class to work with float value."""

    _orig_value: Union[float, int]
    _value: float

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, (float, int)) and not isinstance(source_value, bool):
            self._orig_value = source_value
            self._value = float(source_value)
        else:
            raise ValueError(
                f"Unexpected value for '{type(self)}'."
                f" Expected float, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def __int__(self) -> int:
        return int(self._value)

    def __float__(self) -> float:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        return isinstance(o, FloatBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._orig_value

    @classmethod
    def json_schema(cls: Type["FloatBase"]) -> Dict[Any, Any]:
        return {"type": "number"}


class StrBase(BaseValueType):
    """Base class to work with string value."""

    _orig_value: str
    _value: str

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        if isinstance(source_value, (str, int)) and not isinstance(source_value, bool):
            self._orig_value = str(source_value)
            self._value = str(source_value)
        else:
            raise ValueError(
                f"Unexpected value for '{type(self)}'."
                f" Expected string, got '{source_value}' with type '{type(source_value)}'",
                object_path,
            )

    def __int__(self) -> int:
        raise ValueError("Can't convert string to an integer.")

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value}")'

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, StrBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._orig_value

    @classmethod
    def json_schema(cls: Type["StrBase"]) -> Dict[Any, Any]:
        return {"type": "string"}


class StringLengthBase(StrBase):
    """
    Base class to work with string value length.

    Just inherit the class and set the values for '_min_bytes' and '_max_bytes'.

    class String32B(StringLengthBase):
        _min_bytes: int = 32
    """

    _min_bytes: int = 1
    _max_bytes: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        value_bytes = len(self._value.encode("utf-8"))
        if hasattr(self, "_min_bytes") and (value_bytes < self._min_bytes):
            raise ValueError(
                f"the string value {source_value} is shorter than the minimum {self._min_bytes} bytes.", object_path
            )
        if hasattr(self, "_max_bytes") and (value_bytes > self._max_bytes):
            raise ValueError(
                f"the string value {source_value} is longer than the maximum {self._max_bytes} bytes.", object_path
            )

    @classmethod
    def json_schema(cls: Type["StringLengthBase"]) -> Dict[Any, Any]:
        typ: Dict[str, Any] = {"type": "string"}
        if hasattr(cls, "_min_bytes"):
            typ["minLength"] = cls._min_bytes
        if hasattr(cls, "_max_bytes"):
            typ["maxLength"] = cls._max_bytes
        return typ


class IntRangeBase(IntBase):
    """
    Base class to work with integer value in range.

    Just inherit the class and set the values for '_min' and '_max'.

    class IntNonNegative(IntRangeBase):
        _min: int = 0
    """

    _min: int
    _max: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        if hasattr(self, "_min") and (self._value < self._min):
            raise ValueError(f"value {self._value} is lower than the minimum {self._min}.", object_path)
        if hasattr(self, "_max") and (self._value > self._max):
            raise ValueError(f"value {self._value} is higher than the maximum {self._max}", object_path)

    @classmethod
    def json_schema(cls: Type["IntRangeBase"]) -> Dict[Any, Any]:
        typ: Dict[str, Any] = {"type": "integer"}
        if hasattr(cls, "_min"):
            typ["minimum"] = cls._min
        if hasattr(cls, "_max"):
            typ["maximum"] = cls._max
        return typ


class FloatRangeBase(FloatBase):
    """
    Base class to work with float value in range.

    Just inherit the class and set the values for '_min' and '_max'.

    class FloatNonNegative(IntRangeBase):
        _min: float = 0.0
    """

    _min: float
    _max: float

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        if hasattr(self, "_min") and (self._value < self._min):
            raise ValueError(f"value {self._value} is lower than the minimum {self._min}.", object_path)
        if hasattr(self, "_max") and (self._value > self._max):
            raise ValueError(f"value {self._value} is higher than the maximum {self._max}", object_path)

    @classmethod
    def json_schema(cls: Type["FloatRangeBase"]) -> Dict[Any, Any]:
        typ: Dict[str, Any] = {"type": "number"}
        if hasattr(cls, "_min"):
            typ["minimum"] = cls._min
        if hasattr(cls, "_max"):
            typ["maximum"] = cls._max
        return typ


class PatternBase(StrBase):
    """
    Base class to work with string value that match regex pattern.

    Just inherit the class and set regex pattern for '_re'.

    class ABPattern(PatternBase):
        _re: Pattern[str] = re.compile(r"ab*")
    """

    _re: Pattern[str]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)
        if not type(self)._re.match(self._value):
            raise ValueError(f"'{self._value}' does not match '{self._re.pattern}' pattern", object_path)

    @classmethod
    def json_schema(cls: Type["PatternBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}


class UnitBase(StrBase):
    """
    Base class to work with string value that match regex pattern.

    Just inherit the class and set '_units'.

    class CustomUnit(PatternBase):
        _units = {"b": 1, "kb": 1000}
    """

    _re: Pattern[str]
    _units: Dict[str, int]
    _base_value: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value, object_path)

        type(self)._re = re.compile(rf"^(\d+)({r'|'.join(type(self)._units.keys())})$")
        grouped = self._re.search(self._value)
        if grouped:
            val, unit = grouped.groups()
            if unit is None:
                raise ValueError(f"Missing units. Accepted units are {list(type(self)._units.keys())}", object_path)
            if unit not in type(self)._units:
                raise ValueError(
                    f"Used unexpected unit '{unit}' for {type(self).__name__}."
                    f" Accepted units are {list(type(self)._units.keys())}",
                    object_path,
                )
            self._base_value = int(val) * type(self)._units[unit]
        else:
            raise ValueError(
                f"Unexpected value for '{type(self)}'."
                " Expected string that matches pattern " + rf"'{type(self)._re.pattern}'."
                f" Positive integer and one of the units {list(type(self)._units.keys())}, got '{source_value}'.",
                object_path,
            )

    def __int__(self) -> int:
        return self._base_value

    def __repr__(self) -> str:
        return f"Unit[{type(self).__name__},{self._value}]"

    def __eq__(self, o: object) -> bool:
        """Two instances are equal when they represent the same size regardless of their string representation."""
        return isinstance(o, UnitBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._orig_value

    @classmethod
    def json_schema(cls: Type["UnitBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}
