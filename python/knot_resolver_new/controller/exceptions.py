from typing import List

from knot_resolver import KresBaseError


class KresSubprocessControllerError(KresBaseError):
    """Class for errors that are raised in the controller module."""


class KresSubprocessControllerExec(Exception):  # noqa: N818
    """
    Custom non-error exception that indicates the need for exec().

    Raised by the controller (supervisord) and caught by the controlled process (manager).
    The exception says that the process needs to perform a re-exec during startup.
    This ensures that the process runs under the controller (supervisord) in a process tree hierarchy.
    """

    def __init__(self, exec_args: List[str], *args: object) -> None:
        self.exec_args = exec_args
        super().__init__(*args)
