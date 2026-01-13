from __future__ import annotations

from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

NoneType = type(None)


class BaseType:
    """"""

    def __init__(self, value: Any, tree_path: str = "/", base_path: Path = Path()) -> None:
        self._value = value
        self._tree_path = tree_path
        self._base_path = base_path

    def __repr__(self) -> str:
        cls = self.__class__
        return f'{cls.__name__}("{self._value}")'

    def __eq__(self, o: object) -> bool:
        cls = self.__class__
        return isinstance(o, cls) and o._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __str__(self) -> str:
        return str(self._value)

    def __int__(self) -> int:
        raise NotImplementedError

    def validate() -> None:
        raise NotImplementedError

    @classmethod
    def json_schema(cls) -> dict[Any, Any]:
        raise NotImplementedError
