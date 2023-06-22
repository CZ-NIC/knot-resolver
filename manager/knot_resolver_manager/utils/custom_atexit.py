"""
Custom replacement for standard module `atexit`. We use `atexit` behind the scenes, we just add the option
to invoke the exit functions manually.
"""

import atexit
from typing import Callable, List

_at_exit_functions: List[Callable[[], None]] = []


def register(func: Callable[[], None]) -> None:
    _at_exit_functions.append(func)
    atexit.register(func)


def run_callbacks() -> None:
    for func in _at_exit_functions:
        func()
        atexit.unregister(func)
