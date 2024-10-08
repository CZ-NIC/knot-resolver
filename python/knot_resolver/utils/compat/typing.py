# The 'typing.Pattern' is deprecated since python 3.8 and is removed in version 3.12.
# https://docs.python.org/3.9/library/typing.html#typing.Pattern
try:
    from typing import Pattern
except ImportError:
    from re import Pattern

__all__ = ["Pattern"]
