from __future__ import annotations

from collections import defaultdict
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, ClassVar, cast

from knot_resolver.logging import get_logger

if TYPE_CHECKING:
    from typing import TypeVar

    TSubprocessID = TypeVar("TSubprocessID", bound="SubprocessID")

logger = get_logger(__name__)


class SubprocessType(str, Enum):
    MANAGER = "manager"
    WORKER = "worker"
    LOADER = "loader"
    CACHE_GC = "cache-gc"


class SubprocessStatus(IntEnum):
    STOPPED = 0
    STARTING = 10
    RUNNING = 20
    BACKOFF = 30
    STOPPING = 40
    EXITED = 100
    FATAL = 200
    UNKNOWN = 1000


class SubprocessID:
    __slots__ = ("_num", "_type")

    _num: int
    _type: SubprocessType

    _used: ClassVar[defaultdict[SubprocessType, dict[int, SubprocessID]]] = defaultdict(dict)

    def __new__(cls: type[TSubprocessID], subprocess_type: SubprocessType, subprocess_num: int) -> TSubprocessID:  # noqa: PYI019
        type_used = cls._used[subprocess_type]

        if (used_subprocess_id := type_used.get(subprocess_num)) is not None:
            return cast("TSubprocessID", used_subprocess_id)

        new_subprocess_id = super().__new__(cls)
        new_subprocess_id._num = subprocess_num
        new_subprocess_id._type = subprocess_type
        type_used[subprocess_num] = new_subprocess_id

        return new_subprocess_id

    @classmethod
    def alloc(cls: type[TSubprocessID], subprocess_type: SubprocessType) -> TSubprocessID:  # noqa: PYI019
        type_used = cls._used[subprocess_type]

        subprocess_num = 0
        while subprocess_num in type_used:
            subprocess_num += 1
        return cls(subprocess_type, subprocess_num)

    @property
    def subprocess_num(self) -> int:
        return self._num

    @property
    def subprocess_type(self) -> SubprocessType:
        return self._type

    @property
    def subprocess_name(self) -> str:
        if self._type is SubprocessType.WORKER:
            return f"{self._type}:{self._type}{self._num}"
        return str(self._type.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._type.value}, {self._num})"

    def __hash__(self) -> int:
        return hash((self._type, self._num))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SubprocessID):
            return self._type == other._type and self._num == other._num
        return NotImplemented
