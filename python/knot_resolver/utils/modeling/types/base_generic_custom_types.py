from __future__ import annotations

from typing import Any, Generic, Iterator, List, TypeVar, Union

T = TypeVar("T")


class BaseGenericCustomTypeWrapper(Generic[T]):
    def __init__(self, value: Any) -> None:
        self._value = value

    def __repr__(self) -> str:
        return f'{type(self).__name__}("{self._value!r}")'

    def __str__(self) -> str:
        return str(self._value)

    def __eq__(self, o: object) -> bool:
        if not isinstance(o, type(self)):
            return NotImplemented
        return self._value == o._value


class ListOrItem(BaseGenericCustomTypeWrapper[Union[List[T], T]]):
    def _get_list(self) -> list[T]:
        return self._value if isinstance(self._value, list) else [self._value]

    def __iter__(self) -> Iterator[T]:
        return iter(self._get_list())
