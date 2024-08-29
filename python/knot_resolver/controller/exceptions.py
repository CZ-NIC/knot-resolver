from typing import List

from knot_resolver import KresBaseException


class SubprocessControllerException(KresBaseException):
    pass


class SubprocessControllerExecException(Exception):
    """
    Exception that is used to deliberately terminate system startup
    and make exec() of something else. This is used by the subprocess controller
    as supervisord to run as the top-level process in a process tree hierarchy.
    """

    def __init__(self, exec_args: List[str], *args: object) -> None:
        self.exec_args = exec_args
        super().__init__(*args)
