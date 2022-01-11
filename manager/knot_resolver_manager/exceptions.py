class KresManagerException(Exception):
    """
    Base class for all custom exceptions we use in our code
    """


class SubprocessControllerException(KresManagerException):
    pass


class TreeException(KresManagerException):
    def __init__(self, msg: str, tree_path: str) -> None:
        super().__init__(msg)
        self._tree_path = tree_path

    def where(self) -> str:
        return self._tree_path

    def __str__(self) -> str:
        return super().__str__() + f" @ {self.where()}"


class SchemaException(TreeException):
    pass


class DataException(KresManagerException):
    pass


class ParsingException(KresManagerException):
    pass
