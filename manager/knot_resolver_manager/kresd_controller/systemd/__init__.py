import logging
import os
from enum import Enum, auto
from typing import Iterable, List

from knot_resolver_manager import compat
from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.kres_id import KresID, alloc_from_string
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessInfo,
    SubprocessStatus,
    SubprocessType,
)
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
        id_: KresID,
        systemd_type: systemd.SystemdType,
        persistance_type: SystemdPersistanceType = SystemdPersistanceType.PERSISTENT,
    ):
        self._type = type_
        self._id: KresID = id_
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

    @staticmethod
    def id_could_be_ours(unit_name: str) -> bool:
        is_ours = unit_name == "kres-cache-gc.service"
        is_ours |= unit_name.startswith("kresd") and unit_name.endswith(".service")
        return is_ours

    @property
    def type(self):
        return self._type

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def _on_unexpected_termination(self):
        logger.warning("Detected unexpected termination of unit %s", self.id)

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
            if unit.name.startswith("kresd") and unit.name.endswith(".service"):
                iden = unit.name.replace("kresd", "")[1:].replace(".service", "")
                persistance_type = (
                    SystemdPersistanceType.PERSISTENT if "@" in unit.name else SystemdPersistanceType.TRANSIENT
                )

                if unit.state == "failed":
                    # if a unit is failed, remove it from the system by reseting its state
                    # should work for both transient and persistent units
                    logger.warning("Unit '%s' is already failed, resetting its state and ignoring it", unit.name)
                    await compat.asyncio.to_thread(systemd.reset_failed_unit, self._systemd_type, unit.name)
                    continue

                res.append(
                    SystemdSubprocess(
                        SubprocessType.KRESD,
                        alloc_from_string(iden),
                        self._systemd_type,
                        persistance_type,
                    )
                )
            elif unit.name == "kres-cache-gc.service":
                # we can't easily check, if the unit is transient or not without additional systemd call
                # we ignore it for now and assume the default persistency state. It shouldn't cause any
                # problems, because interactions with the process are done the same way in all cases
                res.append(SystemdSubprocess(SubprocessType.GC, alloc_from_string("gc"), self._systemd_type))
        return res

    async def initialize_controller(self) -> None:
        pass

    async def shutdown_controller(self) -> None:
        pass

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: KresID) -> Subprocess:
        return SystemdSubprocess(subprocess_type, id_hint, self._systemd_type, self._persistance_type)

    async def get_subprocess_info(self) -> List[SubprocessInfo]:
        def convert(u: systemd.Unit) -> SubprocessInfo:
            status_lookup_table = {"failed": SubprocessStatus.FAILED, "running": SubprocessStatus.RUNNING}

            if u.state in status_lookup_table:
                status = status_lookup_table[u.state]
            else:
                status = SubprocessStatus.UNKNOWN

            return SubprocessInfo(id=u.name, status=status)

        return list(map(convert, await to_thread(systemd.list_units, self._systemd_type)))
