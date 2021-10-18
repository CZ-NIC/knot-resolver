from typing import Callable, Iterable, TypeVar

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
