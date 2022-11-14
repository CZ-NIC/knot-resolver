from abc import ABC, abstractmethod
from typing import Any, Dict, List, TypeVar


class Renamed(ABC):
    @abstractmethod
    def original(self) -> Any:
        """
        Returns a data structure, which is the source without dynamic renamings
        """

    @staticmethod
    def map_public_to_private(name: Any) -> Any:
        if isinstance(name, str):
            return name.replace("_", "-")
        return name

    @staticmethod
    def map_private_to_public(name: Any) -> Any:
        if isinstance(name, str):
            return name.replace("-", "_")
        return name


K = TypeVar("K")
V = TypeVar("V")


class RenamedDict(Dict[K, V], Renamed):
    def keys(self) -> Any:
        keys = super().keys()
        return {Renamed.map_private_to_public(key) for key in keys}

    def __getitem__(self, key: K) -> V:
        key = Renamed.map_public_to_private(key)
        res = super().__getitem__(key)
        return renamed(res)

    def __setitem__(self, key: K, value: V) -> None:
        key = Renamed.map_public_to_private(key)
        return super().__setitem__(key, value)

    def __contains__(self, key: object) -> bool:
        key = Renamed.map_public_to_private(key)
        return super().__contains__(key)

    def items(self) -> Any:
        for k, v in super().items():
            yield Renamed.map_private_to_public(k), renamed(v)

    def original(self) -> Dict[K, V]:
        return dict(super().items())


class RenamedList(List[V], Renamed):  # type: ignore
    def __getitem__(self, key: Any) -> Any:
        res = super().__getitem__(key)
        return renamed(res)

    def original(self) -> Any:
        return list(super().__iter__())


def renamed(obj: Any) -> Any:
    if isinstance(obj, dict):
        return RenamedDict(**obj)
    elif isinstance(obj, list):
        return RenamedList(obj)
    else:
        return obj
