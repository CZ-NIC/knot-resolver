import logging
import os
from enum import Enum, auto
from typing import Iterable, List

from knot_resolver_manager import compat
from knot_resolver_manager.kresd_controller.interface import Subprocess, SubprocessController, SubprocessType
from knot_resolver_manager.utils.async_utils import call

from . import dbus_api as systemd

logger = logging.getLogger(__name__)


class SystemdPersistanceType(Enum):
    PERSISTENT = auto()
    TRANSIENT = auto()


class SystemdSubprocess(Subprocess):
    def __init__(
        self,
        type_: SubprocessType,
        id_: str,
        systemd_type: systemd.SystemdType,
        persistance_type: SystemdPersistanceType = SystemdPersistanceType.PERSISTENT,
    ):
        self._type = type_
        self._id = id_
        self._systemd_type = systemd_type
        self._persistance_type = persistance_type

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

    async def start(self):
        if self._persistance_type is SystemdPersistanceType.PERSISTENT:
            await compat.asyncio.to_thread(systemd.start_unit, self._systemd_type, self.id)
        elif self._persistance_type is SystemdPersistanceType.TRANSIENT:
            await compat.asyncio.to_thread(systemd.start_transient_unit, self._systemd_type, self.id, self._type)

    async def stop(self):
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
                res.append(SystemdSubprocess(SubprocessType.KRESD, iden, self._systemd_type, persistance_type))
            elif u == "kres-cache-gc.service":
                res.append(SystemdSubprocess(SubprocessType.GC, "", self._systemd_type))
        return res

    async def initialize_controller(self) -> None:
        pass

    async def shutdown_controller(self) -> None:
        pass

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: str) -> Subprocess:
        return SystemdSubprocess(subprocess_type, id_hint, self._systemd_type, self._persistance_type)
