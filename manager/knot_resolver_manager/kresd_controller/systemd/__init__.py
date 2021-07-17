import logging
import os
from asyncio.futures import Future
from enum import Enum, auto
from typing import Any, Callable, Coroutine, Dict, Iterable, List, Optional, Tuple

from knot_resolver_manager import compat
from knot_resolver_manager.compat.asyncio import create_task
from knot_resolver_manager.kres_id import KresID, alloc, alloc_from_string
from knot_resolver_manager.kresd_controller.interface import Subprocess, SubprocessController, SubprocessType
from knot_resolver_manager.utils.async_utils import call
from knot_resolver_manager.utils.types import NoneType

from . import dbus_api as systemd

logger = logging.getLogger(__name__)


_CallbackType = Callable[[], Coroutine[Any, NoneType, NoneType]]
_callbacks: Dict[Tuple[systemd.SystemdType, str], _CallbackType] = dict()
_dispatcher_task: "Optional[Future[NoneType]]" = None


async def _monitor_unit_termination(type_: systemd.SystemdType) -> NoneType:
    dispatcher = systemd.UnitRemovedEventDispatcher(type_)

    try:
        dispatcher.start()

        while True:
            event = await dispatcher.next_event()
            if (type_, event) in _callbacks:
                await _callbacks[(type_, event)]()
    finally:
        dispatcher.stop()


def _register_terminated_callback(type_: systemd.SystemdType, unit_name: str, callback: _CallbackType):
    assert (type_, unit_name) not in _callbacks
    _callbacks[(type_, unit_name)] = callback

    global _dispatcher_task
    if _dispatcher_task is None:
        _dispatcher_task = create_task(_monitor_unit_termination(type_))


def _unregister_terminated_callback(type_: systemd.SystemdType, unit_name: str):
    del _callbacks[(type_, unit_name)]


class SystemdPersistanceType(Enum):
    PERSISTENT = auto()
    TRANSIENT = auto()


class SystemdSubprocess(Subprocess):
    def __init__(
        self,
        type_: SubprocessType,
        id_: KresID,
        systemd_type: systemd.SystemdType,
        persistance_type: SystemdPersistanceType = SystemdPersistanceType.PERSISTENT,
        already_running: bool = False,
    ):
        self._type = type_
        self._id: KresID = id_
        self._systemd_type = systemd_type
        self._persistance_type = persistance_type

        if already_running:
            _register_terminated_callback(systemd_type, self.id, self._on_unexpected_termination)

    @property
    def id(self):
        if self._type is SubprocessType.GC:
            return "kres-cache-gc.service"
        else:
            sep = {SystemdPersistanceType.PERSISTENT: "@", SystemdPersistanceType.TRANSIENT: "_"}[
                self._persistance_type
            ]
            return f"kresd{sep}{self._id}.service"

    @property
    def type(self):
        return self._type

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def _on_unexpected_termination(self):
        logger.warning("Detected unexpected termination of unit %s", self.id)

    async def start(self):
        _register_terminated_callback(self._systemd_type, self.id, self._on_unexpected_termination)

        if self._persistance_type is SystemdPersistanceType.PERSISTENT:
            await compat.asyncio.to_thread(systemd.start_unit, self._systemd_type, self.id)
        elif self._persistance_type is SystemdPersistanceType.TRANSIENT:
            await compat.asyncio.to_thread(systemd.start_transient_unit, self._systemd_type, self.id, self._type)

    async def stop(self):
        _unregister_terminated_callback(self._systemd_type, self.id)
        await compat.asyncio.to_thread(systemd.stop_unit, self._systemd_type, self.id)

    async def restart(self):
        await compat.asyncio.to_thread(systemd.restart_unit, self._systemd_type, self.id)


class SystemdSubprocessController(SubprocessController):
    def __init__(
        self,
        systemd_type: systemd.SystemdType,
        persistance_type: SystemdPersistanceType = SystemdPersistanceType.PERSISTENT,
    ):
        self._systemd_type = systemd_type
        self._persistance_type = persistance_type
        self._unit_removed_event_dispatcher = systemd.UnitRemovedEventDispatcher(systemd_type)

    def __str__(self):
        if self._systemd_type == systemd.SystemdType.SESSION:
            if self._persistance_type is SystemdPersistanceType.TRANSIENT:
                return "systemd-session-transient"
            else:
                return "systemd-session"
        elif self._systemd_type == systemd.SystemdType.SYSTEM:
            return "systemd"
        else:
            raise NotImplementedError("unknown systemd type")

    async def is_controller_available(self) -> bool:
        # try to run systemctl (should be quite fast)
        cmd = f"systemctl {'--user' if self._systemd_type == systemd.SystemdType.SESSION else ''} status"
        ret = await call(cmd, shell=True, discard_output=True)
        if ret != 0:
            logger.info(
                "Calling '%s' failed. Assumming systemd (%s) is not running/installed.", cmd, self._systemd_type
            )
            return False

        try:
            if self._persistance_type is SystemdPersistanceType.PERSISTENT and not await compat.asyncio.to_thread(
                systemd.can_load_unit, self._systemd_type, "kresd@1.service"
            ):
                logger.info("Systemd (%s) accessible, but no 'kresd@.service' unit detected.", self._systemd_type)
                return False

            if self._systemd_type is systemd.SystemdType.SYSTEM and os.geteuid() != 0:
                logger.info(
                    "Systemd (%s) looks functional, but we are not running as root. Assuming not enough privileges",
                    self._systemd_type,
                )
                return False

            return True
        except BaseException:  # we want every possible exception to be caught
            logger.warning("Communicating with systemd DBus API failed", exc_info=True)
            return False

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        res: List[SystemdSubprocess] = []
        units = await compat.asyncio.to_thread(systemd.list_units, self._systemd_type)
        for unit in units:
            u: str = unit
            if u.startswith("kresd") and u.endswith(".service"):
                iden = u.replace("kresd", "")[1:].replace(".service", "")
                persistance_type = SystemdPersistanceType.PERSISTENT if "@" in u else SystemdPersistanceType.TRANSIENT
                res.append(
                    SystemdSubprocess(
                        SubprocessType.KRESD,
                        alloc_from_string(iden),
                        self._systemd_type,
                        persistance_type,
                        already_running=True,
                    )
                )
            elif u == "kres-cache-gc.service":
                res.append(SystemdSubprocess(SubprocessType.GC, alloc(), self._systemd_type, already_running=True))
        return res

    async def initialize_controller(self) -> None:
        pass

    async def shutdown_controller(self) -> None:
        pass

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: KresID) -> Subprocess:
        return SystemdSubprocess(subprocess_type, id_hint, self._systemd_type, self._persistance_type)
