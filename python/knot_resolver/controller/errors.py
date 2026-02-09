from knot_resolver.errors import BaseKresError


class ControllerError(BaseKresError):
    """Class exception for all errors used in controller submodules."""

    def __init__(self, msg: str) -> None:
        super().__init__()
        self._msg = f"controller error: {msg}"

    def __str__(self) -> str:
        return self._msg
