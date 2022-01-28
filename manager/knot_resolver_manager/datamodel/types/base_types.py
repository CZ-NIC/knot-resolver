import re
from typing import Any, Dict, Pattern, Type

from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils import CustomValueType


class IntBase(CustomValueType):
    """
    Base class to work with integer value.
    """

    _value: int

    def __int__(self) -> int:
        return self._value

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, IntBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["IntBase"]) -> Dict[Any, Any]:
        return {"type": "integer"}


class StrBase(CustomValueType):
    """
    Base class to work with string value.
    """

    _value: str

    def __int__(self) -> int:
        raise ValueError("Can't convert string to an integer.")

    def __str__(self) -> str:
        return self._value

    def to_std(self) -> str:
        return self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __eq__(self, o: object) -> bool:
        return isinstance(o, StrBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value

    @classmethod
    def json_schema(cls: Type["StrBase"]) -> Dict[Any, Any]:
        return {"type": "string"}


class IntRangeBase(IntBase):
    """
    Base class to work with integer value in range.
    Just inherit the class and set the values for '_min' and '_max'.

    class CustomIntRange(IntRangeBase):
        _min: int = 0
        _max: int = 10_000
    """

    _min: int
    _max: int

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
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

    @classmethod
    def json_schema(cls: Type["IntRangeBase"]) -> Dict[Any, Any]:
        return {"type": "integer", "minimum": 0, "maximum": 65_535}


class PatternBase(StrBase):
    """
    Base class to work with string value that match regex pattern.
    Just inherit the class and set regex pattern for '_re'.

    class ABPattern(PatternBase):
        _re: Pattern[str] = re.compile(r"ab*")
    """

    _re: Pattern[str]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        if isinstance(source_value, str):
            if type(self)._re.match(source_value):
                self._value: str = source_value
            else:
                raise SchemaException(f"'{source_value}' does not match '{self._re.pattern}' pattern", object_path)
        else:
            raise SchemaException(
                f"Unexpected input type for string pattern - {type(source_value)}."
                " Cause might be invalid format or invalid type.",
                object_path,
            )

    @classmethod
    def json_schema(cls: Type["PatternBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}


class UnitBase(IntBase):
    """
    Base class to work with string value that match regex pattern.
    Just inherit the class and set '_units'.

    class CustomUnit(PatternBase):
        _units = {"b": 1, "kb": 1000}
    """

    _re: Pattern[str]
    _units: Dict[str, int]
    _value_orig: str

    def __init__(self, source_value: Any, object_path: str = "/") -> None:
        super().__init__(source_value)
        type(self)._re = re.compile(rf"^(\d+)({r'|'.join(type(self)._units.keys())})$")
        if isinstance(source_value, str) and self._re.match(source_value):
            self._value_orig = source_value
            grouped = self._re.search(source_value)
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
        return isinstance(o, UnitBase) and o._value == self._value

    def serialize(self) -> Any:
        return self._value_orig

    @classmethod
    def json_schema(cls: Type["UnitBase"]) -> Dict[Any, Any]:
        return {"type": "string", "pattern": rf"{cls._re.pattern}"}
