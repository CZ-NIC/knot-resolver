"""
This is a compat module that we will use with dataclasses
due to them being unsupported on Python 3.6. However, a proper backport exists.
This module is simply a reimport of that backported library (or the system one),
so that if we have to vendor that library or do something similar with it, we have
the option to do it transparently, without changing anything else.
"""


from dataclasses import dataclass

__all__ = ["dataclass"]
