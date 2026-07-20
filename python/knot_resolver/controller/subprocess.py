from __future__ import annotations

import asyncio
import json
import struct
from collections import defaultdict
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import ClassVar, Self

from knot_resolver.config import KresConfig
from knot_resolver.logging import get_logger

from .config import LOADER_CONFIGFILE_NAME, WORKER_CONFIGFILE_NAME, get_absolute_path
from .supervisord import SupervisordController

logger = get_logger(__name__)


class SubprocessType(StrEnum):
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

    _used: ClassVar[defaultdict[SubprocessType, dict[int, Self]]] = defaultdict(dict)

    def __new__(cls, subprocess_type: SubprocessType, n: int) -> Self:
        used = cls._used[subprocess_type]

        try:
            return used[n]
        except KeyError:
            new_id = super().__new__(cls)
            new_id._num = n
            new_id._type = subprocess_type
            used[n] = new_id
            return new_id

    def __init__(self, subprocess_type: SubprocessType, subprocess_num: int) -> None:
        pass

    @classmethod
    def alloc(cls, subprocess_type: SubprocessType) -> Self:
        used = cls._used[subprocess_type]
        n = 0
        while n in used:
            n += 1
        return cls(subprocess_type, n)

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
        return str(self._type)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self._type!r}, {self._num})"

    def __hash__(self) -> int:
        return hash((self._type, self._num))

    def __eq__(self, o: object) -> bool:
        return isinstance(o, SubprocessID) and self._num == o._num and self._type == o._type


class Subprocess:
    def __init__(self, config: KresConfig, controller: SupervisordController, subprocess_type: SubprocessType) -> None:
        self._id = SubprocessID.alloc(subprocess_type)

        self._config = config
        self._pid: int | None = None
        self._controller = controller

        self._config_file: Path | None = None
        if subprocess_type is SubprocessType.WORKER:
            self._config_file = get_absolute_path(WORKER_CONFIGFILE_NAME)
        elif subprocess_type is SubprocessType.LOADER:
            self._config_file = get_absolute_path(LOADER_CONFIGFILE_NAME)

    @property
    def name(self) -> str:
        return self._id.subprocess_name

    @property
    def type(self) -> SubprocessType:
        return self._id.subprocess_type

    @property
    def pid(self) -> int:
        if self._pid is None:
            supervisord_proxy = self._controller.get_proxy()
            subprocess_info = supervisord_proxy.getProcessInfo(self.name)
            self._pid = int(subprocess_info["pid"])
        return self._pid

    def status(self) -> SubprocessStatus:
        supervisord = self._controller.get_proxy()
        info = supervisord.getProcessInfo(self.name)
        try:
            return SubprocessStatus(info["state"])
        except ValueError:
            return SubprocessStatus.UNKNOWN

    def _render_lua(self) -> str | None:
        if self.type is SubprocessType.WORKER:
            return self._config.render_lua_worker()
        if self.type is SubprocessType.LOADER:
            return self._config.render_lua_loader()
        return None

    def _write_config(self) -> None:
        config_lua = self._render_lua()
        if config_lua and self._config_file:
            with self._config_file.open("w", encoding="utf8") as file:
                file.write(config_lua)

    def _unlink_config(self) -> None:
        if self._config_file:
            self._config_file.unlink(missing_ok=True)

    async def command(self, command: str) -> object:
        if not self._id.subprocess_type is not SubprocessType.WORKER:
            raise RuntimeError("")

        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter | None = None
        try:
            control_socket = Path() / "control" / str(self._id.subprocess_num)
            reader, writer = await asyncio.open_unix_connection(control_socket)

            # drop prompt
            await reader.readexactly(2)

            # switch to JSON mode and send command
            writer.write(b"__json\n")
            writer.write(command.encode() + b"\n")
            await writer.drain()

            # read response
            msg_len = struct.unpack(">I", await reader.readexactly(4))[0]
            result_bytes = await reader.readexactly(msg_len)

            try:
                return json.loads(result_bytes)
            except json.JSONDecodeError:
                return result_bytes.decode()
        finally:
            if writer is not None:
                writer.close()

    async def _start(self) -> None:
        supervisord = self._controller.get_proxy()
        supervisord.startProcess(self.name)

    async def _stop(self) -> None:
        supervisord = self._controller.get_proxy()
        supervisord.stopProcess(self.name)

    async def _restart(self) -> None:
        supervisord = self._controller.get_proxy()
        supervisord.stopProcess(self.name)
        supervisord.startProcess(self.name)
