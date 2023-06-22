"""
This module contains rather simplistic reimplementation of dataclasses due to them being unsupported on Python 3.6
"""


from typing import Any, Dict, Set, Type

dataclasses_import_success = False
try:
    import dataclasses

    dataclasses_import_success = True
except ImportError:
    pass


_CUSTOM_DATACLASS_MARKER = "_CUSTOM_DATACLASS_MARKER"


def dataclass(cls: Any) -> Any:
    if dataclasses_import_success:
        return dataclasses.dataclass(cls)

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


def is_dataclass(obj: Any) -> bool:
    if dataclasses_import_success:
        return dataclasses.is_dataclass(obj)

    return hasattr(obj, _CUSTOM_DATACLASS_MARKER)


__all__ = ["dataclass", "is_dataclass"]
