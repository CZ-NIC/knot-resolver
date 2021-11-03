import logging
import os
from typing import Dict, Iterable, List, Optional

from knot_resolver_manager import compat
from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.kres_id import KresID, alloc_from_string, lookup_from_string
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.utils import phantom_use
from knot_resolver_manager.utils.async_utils import call

from . import dbus_api as systemd

logger = logging.getLogger(__name__)


class SystemdSubprocess(Subprocess):
    def __init__(
        self,
        config: KresConfig,
        typ: SubprocessType,
        id_: KresID,
        systemd_type: systemd.SystemdType,
    ):
        super().__init__(config)
        self._type = typ
        self._id: KresID = id_
        self._systemd_type = systemd_type

    @property
    def id(self) -> KresID:
        return self._id

    @property
    def systemd_id(self) -> str:
        if self._type is SubprocessType.GC:
            return "kres-cache-gc.service"
        else:
            return f"kresd_{self._id}.service"

    @staticmethod
    def is_unit_name_ours(unit_name: str) -> bool:
        is_ours = unit_name == "kres-cache-gc.service"
        is_ours |= unit_name.startswith("kresd_") and unit_name.endswith(".service")
        return is_ours

    @property
    def type(self):
        return self._type

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def _start(self):
        await compat.asyncio.to_thread(
            systemd.start_transient_kresd_unit, self._config, self._systemd_type, self.id, self._type
        )

    async def stop(self):
        await compat.asyncio.to_thread(systemd.stop_unit, self._systemd_type, self.systemd_id)

    async def _restart(self):
        await compat.asyncio.to_thread(systemd.restart_unit, self._systemd_type, self.systemd_id)


class SystemdSubprocessController(SubprocessController):
    def __init__(self, systemd_type: systemd.SystemdType):
        self._systemd_type = systemd_type
        self._controller_config: Optional[KresConfig] = None

    def __str__(self):
        if self._systemd_type == systemd.SystemdType.SESSION:
            return "systemd-session"
        elif self._systemd_type == systemd.SystemdType.SYSTEM:
            return "systemd"
        else:
            raise NotImplementedError("unknown systemd type")

    async def is_controller_available(self, config: KresConfig) -> bool:
        # communication with systemd is not dependent on the config, its always the same
        # so we should just make sure, that analysis tools do not complain
        phantom_use(config)

        # try to run systemctl (should be quite fast)
        cmd = f"systemctl {'--user' if self._systemd_type == systemd.SystemdType.SESSION else ''} status"
        ret = await call(cmd, shell=True, discard_output=True)
        if ret != 0:
            logger.info(
                "Calling '%s' failed. Assumming systemd (%s) is not running/installed.", cmd, self._systemd_type
            )
            return False

        # check that we run under root for non-session systemd
        try:
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
        assert self._controller_config is not None

        res: List[SystemdSubprocess] = []
        units = await compat.asyncio.to_thread(systemd.list_units, self._systemd_type)
        for unit in units:
            if unit.name.startswith("kresd") and unit.name.endswith(".service"):
                iden = unit.name.replace("kresd", "")[1:].replace(".service", "")

                if unit.state == "failed":
                    # if a unit is failed, remove it from the system by reseting its state
                    # should work for both transient and persistent units
                    logger.warning("Unit '%s' is already failed, resetting its state and ignoring it", unit.name)
                    await compat.asyncio.to_thread(systemd.reset_failed_unit, self._systemd_type, unit.name)
                    continue

                res.append(
                    SystemdSubprocess(
                        self._controller_config,
                        SubprocessType.KRESD,
                        alloc_from_string(iden),
                        self._systemd_type,
                    )
                )
            elif unit.name == systemd.GC_SERVICE_NAME:
                # we can't easily check, if the unit is transient or not without additional systemd call
                # we ignore it for now and assume the default persistency state. It shouldn't cause any
                # problems, because interactions with the process are done the same way in all cases
                res.append(
                    SystemdSubprocess(
                        self._controller_config, SubprocessType.GC, alloc_from_string("gc"), self._systemd_type
                    )
                )
        return res

    async def initialize_controller(self, config: KresConfig) -> None:
        self._controller_config = config

    async def shutdown_controller(self) -> None:
        pass

    async def create_subprocess(
        self, subprocess_config: KresConfig, subprocess_type: SubprocessType, id_hint: KresID
    ) -> Subprocess:
        assert self._controller_config is not None
        return SystemdSubprocess(subprocess_config, subprocess_type, id_hint, self._systemd_type)

    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        assert self._controller_config is not None

        def convert(val: str) -> SubprocessStatus:
            status_lookup_table = {"failed": SubprocessStatus.FAILED, "running": SubprocessStatus.RUNNING}
            if val in status_lookup_table:
                return status_lookup_table[val]
            else:
                return SubprocessStatus.UNKNOWN

        data: List[systemd.Unit] = await to_thread(systemd.list_units, self._systemd_type)
        our_data = filter(lambda u: SystemdSubprocess.is_unit_name_ours(u.name), data)
        return {lookup_from_string(u.name): convert(u.state) for u in our_data}
