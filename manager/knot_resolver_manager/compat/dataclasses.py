"""
This is a compat module that we will use with dataclasses
due to them being unsupported on Python 3.6. However, a proper backport exists.
This module is simply a reimport of that backported library (or the system one),
so that if we have to vendor that library or do something similar with it, we have
the option to do it transparently, without changing anything else.
"""


from typing import Any, Dict, Set, Type

_CUSTOM_DATACLASS_MARKER = "_CUSTOM_DATACLASS_MARKER"


def dataclass(cls: Any):
    anot: Dict[str, Type[Any]] = cls.__dict__.get("__annotations__", {})

    def ninit(slf: Any, *args: Any, **kwargs: Any) -> None:
        nonlocal anot

        ianot = iter(anot.keys())
        used: Set[str] = set()

        # set normal arguments
        for arg in args:
            name = next(ianot)
            setattr(slf, name, arg)
            used.add(name)

        # set keyd arguments
        for key, val in kwargs.items():
            assert key in anot, (
                f"Constructing dataclass with an argument '{key}' which is not defined with a type"
                f" annotation in class {cls.__name__}"
            )
            setattr(slf, key, val)
            used.add(key)

        # set default values
        for key in anot:
            if key in used:
                continue
            assert hasattr(
                cls, key
            ), f"Field '{key}' does not have default value and was not defined in the constructor"
            dfl = getattr(cls, key)
            setattr(slf, key, dfl)

    setattr(cls, "__init__", ninit)
    setattr(cls, _CUSTOM_DATACLASS_MARKER, ...)
    return cls


def is_dataclass(cls: Any) -> bool:
    return hasattr(cls, _CUSTOM_DATACLASS_MARKER)


__all__ = ["dataclass", "is_dataclass"]
