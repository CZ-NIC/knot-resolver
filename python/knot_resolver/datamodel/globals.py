"""
The parsing and validation of the datamodel is dependent on a global state:
- a file system path used for resolving relative paths


Commentary from @vsraier:
=========================

While this is not ideal, it is the best we can do at the moment. When I created this module,
the datamodel was dependent on the global state implicitely. The validation procedures just read
the current working directory. This module is the first step in removing the global dependency.

At some point in the future, it might be interesting to add something like a "validation context"
to the modelling tools. It is not technically complicated, but it requires
massive model changes I am not willing to make at the moment. Ideally, when implementing this,
the BaseSchema would turn into an empty class without any logic. Not even a constructor. All logic
would be in the ObjectMapper class. Similar to how Gson works in Java or AutoMapper in C#.
"""

from pathlib import Path
from typing import Optional


class Context:
    resolve_root: Optional[Path]
    strict_validation: bool
    permissions_default: bool

    def __init__(
        self, resolve_root: Optional[Path], strict_validation: bool = True, permissions_default: bool = True
    ) -> None:
        self.resolve_root = resolve_root
        self.strict_validation = strict_validation
        self.permissions_default = permissions_default


_global_context: Context = Context(None)


def set_global_validation_context(context: Context) -> None:
    global _global_context
    _global_context = context


def get_global_validation_context() -> Context:
    return _global_context


def reset_global_validation_context() -> None:
    global _global_context
    _global_context = Context(None)


def get_resolve_root() -> Path:
    if _global_context.resolve_root is None:
        raise RuntimeError(
            "Global validation context 'resolve_root' is not set!"
            " Before validation, you have to set it using `set_global_validation_context()` function!"
        )

    return _global_context.resolve_root


def get_strict_validation() -> bool:
    return _global_context.strict_validation


def get_permissions_default() -> bool:
    return _global_context.permissions_default
