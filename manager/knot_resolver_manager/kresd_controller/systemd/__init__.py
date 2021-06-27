import logging
from typing import Iterable, List

from knot_resolver_manager import compat
from knot_resolver_manager.kresd_controller.interface import Subprocess, SubprocessController, SubprocessType
from knot_resolver_manager.utils.async_utils import call

from . import dbus_api as systemd

logger = logging.getLogger(__name__)


class SystemdSubprocess(Subprocess):
    def __init__(self, type_: SubprocessType, id_: str, systemd_type: systemd.SystemdType):
        self._type = type_
        self._id = id_
        self._systemd_type = systemd_type

    @property
    def id(self):
        return self._id

    @property
    def type(self):
        return self._type

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def start(self):
        await compat.asyncio.to_thread(systemd.start_unit, self._systemd_type, f"kresd@{self.id}.service")

    async def stop(self):
        await compat.asyncio.to_thread(systemd.stop_unit, self._systemd_type, f"kresd@{self.id}.service")

    async def restart(self):
        await compat.asyncio.to_thread(systemd.restart_unit, self._systemd_type, f"kresd@{self.id}.service")


class SystemdSubprocessController(SubprocessController):
    def __init__(self, systemd_type: systemd.SystemdType):
        self._systemd_type = systemd_type

    def __str__(self):
        if self._systemd_type == systemd.SystemdType.SESSION:
            return "SystemdController(SESSION)"
        elif self._systemd_type == systemd.SystemdType.SYSTEM:
            return "SystemdController(SYSTEM)"
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

        # if that passes, try to list units
        try:
            if not compat.asyncio.to_thread(
                systemd.has_some_exec_start_commands, self._systemd_type, "kresd@1.service"
            ):
                logger.info("Systemd (%s) accessible, but no 'kresd@.service' unit detected.", self._systemd_type)
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
            if u.startswith("kresd@") and u.endswith(".service"):
                iden = u.replace("kresd@", "").replace(".service", "")
                res.append(SystemdSubprocess(SubprocessType.KRESD, iden, self._systemd_type))
        return res

    async def initialize_controller(self) -> None:
        pass

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: str) -> Subprocess:
        return SystemdSubprocess(subprocess_type, id_hint, self._systemd_type)
