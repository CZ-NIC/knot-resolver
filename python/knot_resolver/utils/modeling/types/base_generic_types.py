from __future__ import annotations

from typing import Any, Generic, List, TypeVar, Union

from .base_types import BaseType

T = TypeVar("T")


class BaseGenericTypeWrapper(Generic[T], BaseType):
    """"""


class ListOrItem(BaseGenericTypeWrapper[Union[List[T], T]]):
    """"""

    def _get_list(self) -> list[T]:
        return self._value if isinstance(self._value, list) else [self._value]

    def validate(self) -> None:
        self._get_list()

    def __getitem__(self, index: Any) -> T:
        return self._get_list()[index]

    def to_std(self) -> list[T]:
        return self._get_list()

    def __len__(self) -> int:
        return len(self._get_list())

    def serialize(self) -> list[T] | T:
        return self._value
