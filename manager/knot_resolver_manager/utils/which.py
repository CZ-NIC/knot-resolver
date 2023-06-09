import functools
import os
from pathlib import Path


@functools.lru_cache(maxsize=16)
def which(binary_name: str) -> Path:
    """
    Given a name of an executable, search $PATH and return
    the absolute path of that executable. The results of this function
    are LRU cached.

    If not found, throws an RuntimeError.
    """

    possible_directories = os.get_exec_path()
    for dr in possible_directories:
        p = Path(dr, binary_name)
        if p.exists():
            return p.absolute()

    raise RuntimeError(f"Executable {binary_name} was not found in $PATH")
