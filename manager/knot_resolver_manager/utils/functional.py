from enum import Enum, auto
from typing import Any, Callable, Generic, Iterable, TypeVar, Union

T = TypeVar("T")


def foldl(oper: Callable[[T, T], T], default: T, arr: Iterable[T]) -> T:
    val = default
    for x in arr:
        val = oper(val, x)
    return val


def contains_element_matching(cond: Callable[[T], bool], arr: Iterable[T]) -> bool:
    return foldl(lambda x, y: x or y, False, map(cond, arr))


def all_matches(cond: Callable[[T], bool], arr: Iterable[T]) -> bool:
    return foldl(lambda x, y: x and y, True, map(cond, arr))


Succ = TypeVar("Succ")
Err = TypeVar("Err")


class _Status(Enum):
    OK = auto()
    ERROR = auto()


class _ResultSentinel:
    pass


_RESULT_SENTINEL = _ResultSentinel()


class Result(Generic[Succ, Err]):
    @staticmethod
    def ok(succ: T) -> "Result[T, Any]":
        return Result(_Status.OK, succ=succ)

    @staticmethod
    def err(err: T) -> "Result[Any, T]":
        return Result(_Status.ERROR, err=err)

    def __init__(
        self,
        status: _Status,
        succ: Union[Succ, _ResultSentinel] = _RESULT_SENTINEL,
        err: Union[Err, _ResultSentinel] = _RESULT_SENTINEL,
    ) -> None:
        super().__init__()
        self._status: _Status = status
        self._succ: Union[_ResultSentinel, Succ] = succ
        self._err: Union[_ResultSentinel, Err] = err

    def unwrap(self) -> Succ:
        assert self._status is _Status.OK
        assert not isinstance(self._succ, _ResultSentinel)
        return self._succ

    def unwrap_err(self) -> Err:
        assert self._status is _Status.ERROR
        assert not isinstance(self._err, _ResultSentinel)
        return self._err

    def is_ok(self) -> bool:
        return self._status is _Status.OK

    def is_err(self) -> bool:
        return self._status is _Status.ERROR
