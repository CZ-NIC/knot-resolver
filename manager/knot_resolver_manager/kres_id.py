import itertools
import weakref
from typing import Optional

from knot_resolver_manager.utils import ignore_exceptions_optional


class KresID:
    """
    ID object. Effectively only a wrapper around an int, so that the references
    behave normally (bypassing integer interning and other optimizations)
    """

    _used: "weakref.WeakSet[KresID]" = weakref.WeakSet()

    @staticmethod
    def alloc(_custom_name_id: bool = False) -> "KresID":
        for i in itertools.count(start=1):
            val = KresID(i if not _custom_name_id else -i)
            if val not in KresID._used:
                KresID._used.add(val)
                return val

        raise RuntimeError("Reached an end of an infinite loop. How?")

    @staticmethod
    def from_string(val: str) -> "KresID":
        """
        Create a new KresID instance with ID based on the given string. There are no guarantees
        that the returned KresID is unique.
        """
        int_val = ignore_exceptions_optional(int, None, ValueError)(int)(val)
        if int_val is not None:
            res = KresID(int_val)
        else:
            # this would be for example 'gc'
            # we want a special value, so that they do not clash with normal numerical values
            res = KresID.alloc(_custom_name_id=True)
            res.set_custom_str_representation(val)

        KresID._used.add(res)
        return res

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

    def __repr__(self) -> str:
        return f"KresID({self})"

    def __hash__(self) -> int:
        if self._repr:
            return hash(self._repr)
        return self._id

    def __eq__(self, o: object) -> bool:
        if isinstance(o, KresID):
            ret = self._id == o._id
            if self._repr:
                ret |= self._repr == o._repr
            return ret
        return False
