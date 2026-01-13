from __future__ import annotations

from knot_resolver.errors import BaseKresError


class DataModelingError(BaseKresError):
    """Base exception class for all data modeling errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        super().__init__()
        self._msg = f"[{error_path}] {msg}" if error_path else msg
        self._error_path = error_path

    def __str__(self) -> str:
        return self._msg


class DataDescriptionError(DataModelingError):
    """Exception class for data description errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        msg = f"description error: {msg}"
        super().__init__(msg, error_path)


class DataAnnotationError(DataModelingError):
    """Exception class for data annotation errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        msg = f"annotation error: {msg}"
        super().__init__(msg, error_path)


class DataParsingError(DataModelingError):
    """Exception class for data parsing errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        msg = f"parsing error: {msg}"
        super().__init__(msg, error_path)


class DataTypeError(DataModelingError):
    """Exception class for data type errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        msg = f"type error: {msg}"
        super().__init__(msg, error_path)


class DataValueError(DataModelingError):
    """Exception class for data value errors."""

    def __init__(self, msg: str, error_path: str = "") -> None:
        msg = f"value error: {msg}"
        super().__init__(msg, error_path)


class DataValidationError(DataModelingError):
    """
    Exception class for data validation errors.

    This exception is used as parent for other data modeling errors.
    """

    def __init__(self, msg: str, error_path: str, child_errors: list[DataModelingError] | None = None) -> None:
        super().__init__(msg, error_path)

        if child_errors is None:
            child_errors = []
        self._child_errors = child_errors

    def recursive_msg(self, indentation: int = 0) -> str:
        parts: list[str] = []

        if indentation == 0:
            indentation += 1
            parts.append("Data validation error detected:")

        indent = "    " * indentation
        parts.append(f"{indent}{self._msg}")

        if self._child_errors:
            for error in self._child_errors:
                if isinstance(error, DataValidationError):
                    parts.append(error.recursive_msg(indentation + 1))
                else:
                    parts.append(indent + f"    {error}")
        return "\n".join(parts)

    def __str__(self) -> str:
        return self.recursive_msg()


class AggrDataValidationError(DataValidationError):
    """
    Exception class for aggregation of data validation errors.

    This exception is used to aggregate other data modeling errors.
    """

    def __init__(self, error_path: str, child_errors: list[DataModelingError]) -> None:
        super().__init__("error due to lower level error", error_path, child_errors)

    def recursive_msg(self, indentation: int = 0) -> str:
        inc = 0
        parts: list[str] = []

        if indentation == 0:
            inc = 1
            parts.append("Data validation errors detected:")

        for error in self._child_errors:
            if isinstance(error, DataValidationError):
                parts.append(error.recursive_msg(indentation + inc))
            else:
                parts.append(f"    {error}")
        return "\n".join(parts)
