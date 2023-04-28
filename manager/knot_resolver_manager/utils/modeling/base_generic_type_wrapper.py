from typing import Generic, TypeVar

from .base_value_type import BaseTypeABC

T = TypeVar("T")


class BaseGenericTypeWrapper(Generic[T], BaseTypeABC):
    pass
