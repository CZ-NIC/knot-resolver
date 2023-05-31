from typing import Any, List, TypeVar, Union

from knot_resolver_manager.utils.modeling import BaseGenericTypeWrapper

T = TypeVar("T")


class ListOrItem(BaseGenericTypeWrapper[Union[List[T], T]]):
    _value_orig: Union[List[T], T]
    _list: List[T]

    def __init__(self, source_value: Any, object_path: str = "/") -> None:  # pylint: disable=unused-argument
        super().__init__(source_value)
        self._value_orig: Union[List[T], T] = source_value
        self._list: List[T] = source_value if isinstance(source_value, list) else [source_value]

    def __getitem__(self, index: Any) -> T:
        return self._list[index]

    def __int__(self) -> int:
        raise ValueError(f"Can't convert '{type(self).__name__}' to an integer.")

    def __str__(self) -> str:
        return str(self._value_orig)

    def to_std(self) -> List[T]:
        return self._list

    def __eq__(self, o: object) -> bool:
        return isinstance(o, ListOrItem) and o._value_orig == self._value_orig

    def serialize(self) -> Union[List[T], T]:
        return self._value_orig
