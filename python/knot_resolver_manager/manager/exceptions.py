from typing import List


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
