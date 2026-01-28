from typing import Iterable, Iterator

from knot_resolver import KresBaseError


class ModelingBaseError(KresBaseError):
    """Base class for all errors used in data modeling."""


class DataDescriptionError(ModelingBaseError):
    """Class for errors that are raised when checking data description."""


class DataParsingError(ModelingBaseError):
    """Class for errors that are raised when parsing data."""


class DataValidationError(ModelingBaseError):
    """Class for errors that are raised when validating data."""

    def __init__(self, msg: str, tree_path: str, child_exceptions: Iterable["DataValidationError"] = ()) -> None:
        super().__init__(msg)
        self._tree_path = tree_path.replace("_", "-")
        self._child_exceptions = child_exceptions

    def where(self) -> str:
        return self._tree_path

    def msg(self) -> str:
        return f"[{self.where()}] {super().__str__()}"

    def recursive_msg(self, indentation_level: int = 0) -> str:
        def indented_lines(level: int) -> Iterator[str]:
            if level == 0:
                yield "Configuration validation error detected:"
                level += 1

            indent = "\t" * level
            yield f"{indent}{self.msg()}"

            for child in self._child_exceptions:
                yield from child.recursive_msg(level + 1).split("\n")

        return "\n".join(indented_lines(indentation_level))

    def __str__(self) -> str:
        return self.recursive_msg()


class AggregateDataValidationError(DataValidationError):
    """Aggregation class for errors (DataValidationError) raised during data validation."""

    def __init__(self, object_path: str, child_exceptions: Iterable[DataValidationError]) -> None:
        super().__init__("error due to lower level exceptions", object_path, child_exceptions)

    def recursive_msg(self, indentation_level: int = 0) -> str:
        def indented_lines(level: int) -> Iterator[str]:
            inc = 0
            if level == 0:
                yield "Configuration validation errors detected:"
                inc = 1

            for child in self._child_exceptions:
                yield from child.recursive_msg(level + inc).split("\n")

        return "\n".join(indented_lines(indentation_level))
