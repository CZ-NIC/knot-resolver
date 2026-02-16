from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

if TYPE_CHECKING:
    from knot_resolver.utils.modeling.context import Context

T = TypeVar("T")

NoneType = type(None)


class BaseCustomType(ABC):
    """
    Base class for custom types that just wraps the value.

    This class provides the basis for other custom types.
    """

    def __init__(self, value: Any, tree_path: str = "/", base_path: Path = Path()) -> None:
        self._value = value
        self._tree_path = tree_path
        self._base_path = base_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value!r}")'

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, type(self)):
            return NotImplemented
        return self._value == o._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __str__(self) -> str:
        return str(self._value)

    def __int__(self) -> int:
        msg = f"int() not supported for {type(self).__name__}"
        raise TypeError(msg)

    def __float__(self) -> float:
        msg = f"float() not supported for {type(self).__name__}"
        raise TypeError(msg)

    @abstractmethod
    def validate(self, context: Context) -> None:
        """
        Validate data wrapped by the custom type.

        Args:
            context (Context):
                Validation context for the validation operations, e.g. validation strictness
                or username and groupname to check permissions on paths.

        Raises:
            DataTypeError: When input data type validation fails.
            DataValueError: When input data value validation fails.
            DataValidationError: When some other input data validation fails.
        """

    @classmethod
    @abstractmethod
    def json_schema(cls) -> dict[Any, Any]:
        """
        Get JSON schema of the custom type.

        Returns:
            JSON schema of the custom type in dictionary.
        """
