from typing import Iterable, List


class CancelStartupExecInsteadException(Exception):
    """
    Exception used for terminating system startup and instead
    causing an exec of something else. Could be used by subprocess
    controllers such as supervisord to allow them to run as top-level
    process in a process tree.
    """
    def __init__(self, exec_args: List[str], *args: object) -> None:
        self.exec_args = exec_args
        super().__init__(*args)


class KresManagerException(Exception):
    """
    Base class for all custom exceptions we use in our code
    """


class SubprocessControllerException(KresManagerException):
    pass


class SubprocessControllerTimeoutException(KresManagerException):
    pass


class SchemaException(KresManagerException):
    def __init__(self, msg: str, tree_path: str, child_exceptions: "Iterable[SchemaException]" = tuple()) -> None:
        super().__init__(msg)
        self._tree_path = tree_path
        self._child_exceptions = child_exceptions

    def where(self) -> str:
        return self._tree_path

    def msg(self):
        return f"[{self.where()}] " + super().__str__()

    def recursive_msg(self, indentation_level: int = 0) -> str:
        INDENT = indentation_level * "\t"
        msg_parts: List[str] = [f"{INDENT}{self.msg()}"]
        for c in self._child_exceptions:
            msg_parts.append(c.recursive_msg(indentation_level + 1))
        return "\n".join(msg_parts)

    def __str__(self) -> str:
        return self.recursive_msg()


class AggregateSchemaException(SchemaException):
    def __init__(self, object_path: str, child_exceptions: "Iterable[SchemaException]") -> None:
        super().__init__("error due to lower level exceptions", object_path, child_exceptions)

    def recursive_msg(self, indentation_level: int = 0) -> str:
        inc = 0
        msg_parts: List[str] = []
        if indentation_level == 0:
            inc = 1
            msg_parts.append("multiple configuration errors detected:")

        for c in self._child_exceptions:
            msg_parts.append(c.recursive_msg(indentation_level + inc))
        return "\n".join(msg_parts)


class DataException(KresManagerException):
    pass


class ParsingException(KresManagerException):
    pass
