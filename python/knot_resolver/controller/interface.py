import asyncio
import itertools
import json
import logging
import struct
import sys
from abc import ABC, abstractmethod  # pylint: disable=no-name-in-module
from enum import Enum, auto
from pathlib import Path
from typing import Dict, Iterable, Optional, Type, TypeVar
from weakref import WeakValueDictionary

from knot_resolver.controller.exceptions import SubprocessControllerError
from knot_resolver.controller.registered_workers import register_worker, unregister_worker
from knot_resolver.datamodel.config_schema import KresConfig
from knot_resolver.manager.constants import kresd_config_file, policy_loader_config_file

logger = logging.getLogger(__name__)


class SubprocessType(Enum):
    KRESD = auto()
    POLICY_LOADER = auto()
    GC = auto()


class SubprocessStatus(Enum):
    RUNNING = auto()
    FATAL = auto()
    EXITED = auto()
    UNKNOWN = auto()


T = TypeVar("T", bound="KresID")


class KresID:
    """
    ID object used for identifying subprocesses.
    """

    _used: "Dict[SubprocessType, WeakValueDictionary[int, KresID]]" = {k: WeakValueDictionary() for k in SubprocessType}

    @classmethod
    def alloc(cls: Type[T], typ: SubprocessType) -> T:
        # find free ID closest to zero
        for i in itertools.count(start=0, step=1):
            if i not in cls._used[typ]:
                return cls.new(typ, i)

        raise RuntimeError("Reached an end of an infinite loop. How?")

    @classmethod
    def new(cls: "Type[T]", typ: SubprocessType, n: int) -> "T":
        if n in cls._used[typ]:
            # Ignoring typing here, because I can't find a way how to make the _used dict
            # typed based on subclass. I am not even sure that it's different between subclasses,
            # it's probably still the same dict. But we don't really care about it
            return cls._used[typ][n]  # type: ignore
        val = cls(typ, n, _i_know_what_i_am_doing=True)
        cls._used[typ][n] = val
        return val

    def __init__(self, typ: SubprocessType, n: int, _i_know_what_i_am_doing: bool = False):
        if not _i_know_what_i_am_doing:
            raise RuntimeError("Don't do this. You seem to have no idea what it does")

        self._id = n
        self._type = typ

    @property
    def subprocess_type(self) -> SubprocessType:
        return self._type

    def __repr__(self) -> str:
        return f"KresID({self})"

    def __hash__(self) -> int:
        return self._id

    def __eq__(self, o: object) -> bool:
        if isinstance(o, KresID):
            return self._type == o._type and self._id == o._id
        return False

    def __str__(self) -> str:
        """
        Returns string representation of the ID usable directly in the underlying service manager
        """
        raise NotImplementedError()

    @staticmethod
    def from_string(val: str) -> "KresID":
        """
        Inverse of __str__
        """
        raise NotImplementedError()

    def __int__(self) -> int:
        return self._id


class Subprocess(ABC):
    """
    One SubprocessInstance corresponds to one manager's subprocess
    """

    def __init__(self, config: KresConfig, kresid: KresID) -> None:
        self._id = kresid
        self._config = config
        self._registered_worker: bool = False

        self._config_file: Optional[Path] = None
        if self.type is SubprocessType.KRESD:
            self._config_file = kresd_config_file(self._config, self.id)
        elif self.type is SubprocessType.POLICY_LOADER:
            self._config_file = policy_loader_config_file(self._config)

    def _render_lua(self) -> Optional[str]:
        if self.type is SubprocessType.KRESD:
            return self._config.render_lua()
        if self.type is SubprocessType.POLICY_LOADER:
            return self._config.render_lua_policy()
        return None

    def _write_config(self) -> None:
        config_lua = self._render_lua()
        if config_lua and self._config_file:
            with open(self._config_file, "w", encoding="utf8") as file:
                file.write(config_lua)

    def _unlink_config(self) -> None:
        if self._config_file:
            self._config_file.unlink(missing_ok=True)

    async def start(self, new_config: Optional[KresConfig] = None) -> None:
        if new_config:
            self._config = new_config
        self._write_config()

        try:
            await self._start()
            if self.type is SubprocessType.KRESD:
                register_worker(self)
                self._registered_worker = True
        except SubprocessControllerError as e:
            self._unlink_config()
            raise e

    async def apply_new_config(self, new_config: KresConfig) -> None:
        self._config = new_config

        # update config file
        logger.debug(f"Writing config file for {self.id}")
        self._write_config()

        # update runtime status
        logger.debug(f"Restarting {self.id}")
        await self._restart()

    async def stop(self) -> None:
        if self._registered_worker:
            unregister_worker(self)
        await self._stop()
        await self.cleanup()

    async def cleanup(self) -> None:
        """
        Remove temporary files and all traces of this instance running. It is NOT SAFE to call this while
        the kresd is running, because it will break automatic restarts (at the very least).
        """
        self._unlink_config()

    def __eq__(self, o: object) -> bool:
        return isinstance(o, type(self)) and o.type == self.type and o.id == self.id

    def __hash__(self) -> int:
        return hash(type(self)) ^ hash(self.type) ^ hash(self.id)

    @abstractmethod
    async def _start(self) -> None:
        pass

    @abstractmethod
    async def _stop(self) -> None:
        pass

    @abstractmethod
    async def _restart(self) -> None:
        pass

    @abstractmethod
    def status(self) -> SubprocessStatus:
        pass

    @property
    def type(self) -> SubprocessType:
        return self.id.subprocess_type

    @property
    def id(self) -> KresID:
        return self._id

    async def command(self, cmd: str) -> object:
        if not self._registered_worker:
            raise RuntimeError("the command cannot be sent to a process other than the kresd worker")

        reader: asyncio.StreamReader
        writer: Optional[asyncio.StreamWriter] = None

        try:
            reader, writer = await asyncio.open_unix_connection(f"./control/{int(self.id)}")

            # drop prompt
            _ = await reader.read(2)

            # switch to JSON mode
            writer.write("__json\n".encode("utf8"))

            # write command
            writer.write(cmd.encode("utf8"))
            writer.write(b"\n")
            await writer.drain()

            # read result
            (msg_len,) = struct.unpack(">I", await reader.read(4))
            result_bytes = await reader.readexactly(msg_len)
            return json.loads(result_bytes.decode("utf8"))

        finally:
            if writer is not None:
                writer.close()

                # proper closing of the socket is only implemented in later versions of python
                if sys.version_info.minor >= 7:
                    await writer.wait_closed()  # type: ignore


class SubprocessController(ABC):
    """
    The common Subprocess Controller interface. This is what KresManager requires and what has to be implemented by all
    controllers.
    """

    @abstractmethod
    async def is_controller_available(self, config: KresConfig) -> bool:
        """
        Returns bool, whether the controller is available with the given config
        """

    @abstractmethod
    async def initialize_controller(self, config: KresConfig) -> None:
        """
        Should be called when we want to really start using the controller with a specific configuration
        """

    @abstractmethod
    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        """

        Must NOT be called before initialize_controller()
        """

    @abstractmethod
    async def shutdown_controller(self) -> None:
        """
        Called when the manager is gracefully shutting down. Allows us to stop
        the service manager process or simply cleanup, so that we don't reuse
        the same resources in a new run.

        Must NOT be called before initialize_controller()
        """

    @abstractmethod
    async def create_subprocess(self, subprocess_config: KresConfig, subprocess_type: SubprocessType) -> Subprocess:
        """
        Return a Subprocess object which can be operated on. The subprocess is not
        started or in any way active after this call. That has to be performaed manually
        using the returned object itself.

        Must NOT be called before initialize_controller()
        """

    @abstractmethod
    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        """
        Get a status of running subprocesses as seen by the controller. This method  actively polls
        for information.

        Must NOT be called before initialize_controller()
        """
