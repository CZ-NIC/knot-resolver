from typing import Iterable, List

from knot_resolver import KresBaseException


class DataModelingBaseException(KresBaseException):
    """
    Base class for all exceptions used in modelling.
    """


class DataParsingError(DataModelingBaseException):
    pass


class DataDescriptionError(DataModelingBaseException):
    pass


class DataValidationError(DataModelingBaseException):
    def __init__(self, msg: str, tree_path: str, child_exceptions: "Iterable[DataValidationError]" = tuple()) -> None:
        super().__init__(msg)
        self._tree_path = tree_path.replace("_", "-")
        self._child_exceptions = child_exceptions

    def where(self) -> str:
        return self._tree_path

    def msg(self):
        return f"[{self.where()}] {super().__str__()}"

    def recursive_msg(self, indentation_level: int = 0) -> str:
        msg_parts: List[str] = []

        if indentation_level == 0:
            indentation_level += 1
            msg_parts.append("Configuration validation error detected:")

        indent = indentation_level * "\t"
        msg_parts.append(f"{indent}{self.msg()}")

        for c in self._child_exceptions:
            msg_parts.append(c.recursive_msg(indentation_level + 1))
        return "\n".join(msg_parts)

    def __str__(self) -> str:
        return self.recursive_msg()


class AggregateDataValidationError(DataValidationError):
    def __init__(self, object_path: str, child_exceptions: "Iterable[DataValidationError]") -> None:
        super().__init__("error due to lower level exceptions", object_path, child_exceptions)

    def recursive_msg(self, indentation_level: int = 0) -> str:
        inc = 0
        msg_parts: List[str] = []
        if indentation_level == 0:
            inc = 1
            msg_parts.append("Configuration validation errors detected:")

        for c in self._child_exceptions:
            msg_parts.append(c.recursive_msg(indentation_level + inc))
        return "\n".join(msg_parts)
