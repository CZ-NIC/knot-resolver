from __future__ import annotations

from collections import defaultdict
from enum import Enum, IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from knot_resolver.logging import get_logger

from .config import LOADER_CONFIGFILE_NAME, WORKER_CONFIGFILE_NAME
from .exceptions import ControllerError

if TYPE_CHECKING:
    from typing import TypeVar

    from knot_resolver.datamodel import KresConfig

    from .supervisord import SupervisordController, SupervisorRPC

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

    @classmethod
    def from_name(cls: type[TSubprocessID], name: str) -> TSubprocessID:  # noqa: PYI019
        if name == "cache-gc":
            return cls(SubprocessType.CACHE_GC, 0)
        if name == "loader":
            return cls(SubprocessType.LOADER, 0)
        if name.startswith("worker"):
            return cls(SubprocessType.WORKER, int(name.removeprefix("worker")))
        if name == "manager":
            return cls(SubprocessType.MANAGER, 0)
        msg = f"Unexpected subprocess name: {name}"
        raise ValueError(msg)

    @property
    def subprocess_num(self) -> int:
        return self._num

    @property
    def subprocess_type(self) -> SubprocessType:
        return self._type

    @property
    def subprocess_name(self) -> str:
        if self._type is SubprocessType.WORKER:
            return f"{self._type.value}{self._num}"
        return str(self._type.value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._type.value}, {self._num})"

    def __hash__(self) -> int:
        return hash((self._type, self._num))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SubprocessID):
            return self._type == other._type and self._num == other._num
        return NotImplemented


class Subprocess:
    def __init__(self, subprocess_type: SubprocessType, controller: SupervisordController) -> None:
        self._id = SubprocessID.alloc(subprocess_type)
        self._controller = controller

        self._pid: int | None = None
        self._config_file: Path | None = None

    @property
    def id(self) -> SubprocessID:
        return self._id

    @property
    def name(self) -> str:
        return self._id.subprocess_name

    @property
    def type(self) -> SubprocessType:
        return self._id.subprocess_type

    @property
    def full_name(self) -> str:
        return f"{self.type}:{self.name}"

    async def start(self, config: KresConfig) -> None:
        self._write_config_file(config)
        try:
            logger.debug("Starting %s subprocess...", self.name)
            await self._start()
        except ControllerError:
            await self.cleanup()
            raise

    async def stop(self) -> None:
        logger.debug("Stopping %s subprocess...", self.name)
        await self._stop()
        await self.cleanup()

    async def reconfig(self, new_config: KresConfig) -> None:
        self._write_config_file(new_config)
        logger.debug("Restarting %s subprocess...", self.name)
        await self._restart()

    async def cleanup(self) -> None:
        self._unlink_config_file()

    def get_pid(self) -> int:
        if self._pid is None:
            subprocess_info = self._get_info()
            self._pid = cast("int", subprocess_info["pid"])
        return self._pid

    def get_status(self) -> SubprocessStatus:
        subprocess_info = self._get_info()
        try:
            return SubprocessStatus(cast("int", subprocess_info["state"]))
        except ValueError:
            return SubprocessStatus.UNKNOWN

    async def _start(self) -> None:
        supervisord = self._get_controller_proxy()
        supervisord.startProcess(self.full_name)

    async def _stop(self) -> None:
        supervisord = self._get_controller_proxy()
        supervisord.stopProcess(self.full_name)

    async def _restart(self) -> None:
        supervisord = self._get_controller_proxy()
        supervisord.stopProcess(self.full_name)
        supervisord.startProcess(self.full_name)

    def _write_config_file(self, config: KresConfig) -> None:
        if self.type is SubprocessType.WORKER:
            config_lua = config.render_worker_lua()
            config_file_name = WORKER_CONFIGFILE_NAME % {"process_num": self._id.subprocess_num}
        elif self.type is SubprocessType.LOADER:
            config_lua = config.render_loader_lua()
            config_file_name = LOADER_CONFIGFILE_NAME
        else:
            logger.error("Writing config file is not supported for %s subprocess", self.name)
            return

        config_file = Path(config_file_name).absolute()
        logger.debug("Writing config for %s subprocess to %s file", self.name, config_file)
        config_file.write_text(config_lua, encoding="utf-8")
        self._config_file = config_file

    def _unlink_config_file(self) -> None:
        if self._config_file:
            self._config_file.unlink(missing_ok=True)

    def _get_controller_proxy(self) -> SupervisorRPC:
        return self._controller.get_proxy()

    def _get_info(self) -> dict[str, object]:
        return self._get_controller_proxy().getProcessInfo(self.name)
