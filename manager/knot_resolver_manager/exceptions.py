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


class DataParsingException(TreeException):
    pass


class DataValidationException(TreeException):
    pass


class ParsingException(KresdManagerException):
    pass


class ValidationException(KresdManagerException):
    pass
