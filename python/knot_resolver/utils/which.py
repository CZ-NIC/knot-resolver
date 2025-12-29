import functools
import os
from pathlib import Path


@functools.lru_cache(maxsize=16)
def which(binary_name: str) -> Path:
    """
    Get absolute path of an executable given name.

    Searches in $PATH.
    The result of the function is LRU cached.

    Args:
        binary_name (str): The name of the executable binary.

    Returns:
        Path: Absolute path of the executable.

    Raises:
        RuntimeError: If the executable was not found.

    """
    possible_directories = os.get_exec_path()
    for dr in possible_directories:
        exec_path = Path(dr, binary_name)
        if exec_path.exists():
            return exec_path.absolute()

    msg = f"The executable '{binary_name}' was not found in $PATH"
    raise RuntimeError(msg)
