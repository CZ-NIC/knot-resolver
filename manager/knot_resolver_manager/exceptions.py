class KresdManagerException(Exception):
    """
    Base class for all custom exceptions we use in our code
    """


class SubprocessControllerException(KresdManagerException):
    pass


class TreeException(KresdManagerException):
    def __init__(self, msg: str, tree_path: str) -> None:
        super().__init__(msg)
        self._tree_path = tree_path

    def where(self) -> str:
        return self._tree_path


class SchemaException(TreeException):
    pass


class DataException(KresdManagerException):
    pass


class ParsingException(KresdManagerException):
    pass
