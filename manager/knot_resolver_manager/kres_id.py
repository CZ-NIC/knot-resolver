import itertools
import weakref
from typing import Optional

from knot_resolver_manager.utils import ignore_exceptions_optional


class KresID:
    """
    ID object. Effectively only a wrapper around an int, so that the references
    behave normally (bypassing integer interning and other optimizations)
    """

    def __init__(self, n: int):
        self._id = n
        self._repr: Optional[str] = None

    def set_custom_str_representation(self, representation: str) -> None:
        self._repr = representation

    def __str__(self) -> str:
        if self._repr is None:
            return str(self._id)
        else:
            return self._repr

    def __hash__(self) -> int:
        return self._id

    def __eq__(self, o: object) -> bool:
        return isinstance(o, KresID) and self._id == o._id


_used: "weakref.WeakSet[KresID]" = weakref.WeakSet()


def alloc(_custom_name_id: bool = False) -> KresID:
    for i in itertools.count(start=1):
        val = KresID(i if not _custom_name_id else -i)
        if val not in _used:
            _used.add(val)
            return val

    raise RuntimeError("Reached an end of an infinite loop. How?")


def alloc_from_string(val: str) -> KresID:
    int_val = ignore_exceptions_optional(int, None, ValueError)(int)(val)
    if int_val is not None:
        res = KresID(int_val)
        assert res not in _used, "Force allocating a KresID, which already exists..."
        _used.add(res)
        return res
    else:
        # this would be for example 'gc'
        # we want a special value, so that they do not clash with normal numerical values
        res = alloc(_custom_name_id=True)
        res.set_custom_str_representation(val)
        return res


def lookup_from_string(val: str) -> KresID:
    for allocated_id in _used:
        if str(allocated_id) == val:
            return allocated_id

    raise IndexError(f"ID with identifier '{val}' was not allocated")
