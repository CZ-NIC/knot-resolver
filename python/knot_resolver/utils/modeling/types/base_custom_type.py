from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, TypeVar

from knot_resolver.utils.modeling.context import Context, Strictness

T = TypeVar("T")

NoneType = type(None)


class BaseCustomType(ABC):
    """
    Base class for custom types that just wraps the value.

    This class provides the basis for other custom types.
    """

    _is_valid: bool = False

    def __init__(self, value: Any, tree_path: str = "/", base_path: Path = Path()) -> None:
        self._value = value
        self._tree_path = tree_path
        self._base_path = base_path

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value!r}")'

    def __eq__(self, obj: object) -> bool:
        if not isinstance(obj, type(self)):
            return NotImplemented
        return self._value == obj._value

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
    def _validate(self, context: Context) -> None:
        """
        Validate data value wrapped by the custom type.

        All validation should be done here.
        This method is automatically called during validation.
        Subclasses must implement this method.
        """

    def validate(self, context: Context | None = None) -> None:
        """
        Validate data value wrapped by the custom type.

        Args:
            context (Context | None):
                Optional, validation context for the validation operations, e.g. validation strictness
                or username and groupname to check permissions on paths.
                If set to None, Context() with defaults is used.

        Raises:
            DataTypeError: When input data type validation fails.
            DataValueError: When input data value validation fails.
            DataValidationError: When some other input data validation fails.

        At least BASIC validation strictness is required
        for the data value to be considered valid.
        If validation is successful, no error is raised.
        """

        if context is None:
            # use default context
            context = Context()

        if context.strictness > Strictness.PERMISSIVE:
            self._validate(context)
            self._is_valid = True

    @classmethod
    @abstractmethod
    def json_schema(cls) -> dict[Any, Any]:
        """
        Get JSON schema of the custom type.

        Returns:
            JSON schema of the custom type in dictionary.
        """
