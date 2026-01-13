from __future__ import annotations


class DataModelingBaseError(BaseException):
    """Base exception class that is used for all data modeling errors."""


class DataDescriptionError(DataModelingBaseError):
    """Exception class that is used for data description errors."""


class DataParsingError(DataModelingBaseError):
    """Exception class that is used for data parsing errors."""


class DataValidationError(DataModelingBaseError):
    """Exception class that is used for data validation errors."""

    def __init__(self, msg: str, error_path: str, child_errors: list[DataValidationError] | None = None) -> None:
        if child_errors is None:
            child_errors = []
        if child_errors is None:
            child_errors = []
        super().__init__(msg)
        self._msg = f"[{error_path}] {msg}"
        self._error_path = error_path
        self._child_errors = child_errors

    def recursive_msg(self, indentation: int = 0) -> str:
        parts: list[str] = []

        if indentation == 0:
            indentation += 1
            parts.append("Configuration validation error detected:")

        indent = "    " * indentation
        parts.append(f"{indent}{self._msg}")

        if self._child_errors:
            parts += [error.recursive_msg(indentation + 1) for error in self._child_errors]
        return "\n".join(parts)

    def __str__(self) -> str:
        return self.recursive_msg()


class AggregateDataValidationError(DataValidationError):
    """Exception class that is used to aggregate data validation errors."""

    def __init__(self, error_path: str, child_errors: list[DataValidationError]) -> None:
        super().__init__("error due to lower level error", error_path, child_errors)

    def recursive_msg(self, indentation: int = 0) -> str:
        inc = 0
        parts: list[str] = []

        if indentation == 0:
            inc = 1
            parts.append("Configuration validation errors detected:")
        parts += [error.recursive_msg(indentation + inc) for error in self._child_errors]

        return "\n".join(parts)
