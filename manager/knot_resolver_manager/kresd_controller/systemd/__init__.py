import logging
import os
from typing import Dict, Iterable, List, Optional

from knot_resolver_manager import compat
from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.kres_id import KresID
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.kresd_controller.systemd.dbus_api import (
    GC_SERVICE_NAME,
    SystemdType,
    Unit,
    is_service_name_ours,
    kres_id_from_service_name,
    list_units,
    reset_failed_unit,
    restart_unit,
    service_name_from_kres_id,
    start_transient_kresd_unit,
    stop_unit,
)
from knot_resolver_manager.utils import phantom_use
from knot_resolver_manager.utils.async_utils import call

logger = logging.getLogger(__name__)


class SystemdSubprocess(Subprocess):
    def __init__(
        self, config: KresConfig, typ: SubprocessType, systemd_type: SystemdType, custom_id: Optional[KresID] = None
    ):
        super().__init__(config, typ, custom_id=custom_id)
        self._systemd_type = systemd_type

    async def _start(self):
        await compat.asyncio.to_thread(
            start_transient_kresd_unit, self._config, self._systemd_type, self.id, self._type
        )

    async def _stop(self):
        await compat.asyncio.to_thread(stop_unit, self._systemd_type, service_name_from_kres_id(self.id))

    async def _restart(self):
        await compat.asyncio.to_thread(restart_unit, self._systemd_type, service_name_from_kres_id(self.id))


class SystemdSubprocessController(SubprocessController):
    def __init__(self, systemd_type: SystemdType):
        self._systemd_type = systemd_type
        self._controller_config: Optional[KresConfig] = None

    def __str__(self):
        if self._systemd_type == SystemdType.SESSION:
            return "systemd-session"
        elif self._systemd_type == SystemdType.SYSTEM:
            return "systemd"
        else:
            raise NotImplementedError("unknown systemd type")

    async def is_controller_available(self, config: KresConfig) -> bool:
        # communication with systemd is not dependent on the config, its always the same
        # so we should just make sure, that analysis tools do not complain
        phantom_use(config)

        # try to run systemctl (should be quite fast)
        cmd = f"systemctl {'--user' if self._systemd_type == SystemdType.SESSION else ''} status"
        ret = await call(cmd, shell=True, discard_output=True)
        if ret != 0:
            logger.info(
                "Calling '%s' failed. Assumming systemd (%s) is not running/installed.", cmd, self._systemd_type
            )
            return False

        # check that we run under root for non-session systemd
        try:
            if self._systemd_type is SystemdType.SYSTEM and os.geteuid() != 0:
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
        units = await compat.asyncio.to_thread(list_units, self._systemd_type)
        for unit in units:
            if is_service_name_ours(unit.name):
                if unit.state == "failed":
                    # if a unit is failed, remove it from the system by reseting its state
                    logger.warning("Unit '%s' is already failed, resetting its state and ignoring it", unit.name)
                    await compat.asyncio.to_thread(reset_failed_unit, self._systemd_type, unit.name)
                    continue

                res.append(
                    SystemdSubprocess(
                        self._controller_config,
                        SubprocessType.GC if unit.name == GC_SERVICE_NAME else SubprocessType.KRESD,
                        self._systemd_type,
                        custom_id=kres_id_from_service_name(unit.name),
                    )
                )

        return res

    async def initialize_controller(self, config: KresConfig) -> None:
        self._controller_config = config

    async def shutdown_controller(self) -> None:
        pass

    async def create_subprocess(self, subprocess_config: KresConfig, subprocess_type: SubprocessType) -> Subprocess:
        assert self._controller_config is not None
        custom_id = KresID.from_string(GC_SERVICE_NAME) if subprocess_type == SubprocessType.GC else None
        return SystemdSubprocess(subprocess_config, subprocess_type, self._systemd_type, custom_id=custom_id)

    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        assert self._controller_config is not None

        def convert(val: str) -> SubprocessStatus:
            status_lookup_table = {"failed": SubprocessStatus.FAILED, "running": SubprocessStatus.RUNNING}
            if val in status_lookup_table:
                return status_lookup_table[val]
            else:
                return SubprocessStatus.UNKNOWN

        data: List[Unit] = await to_thread(list_units, self._systemd_type)
        our_data = filter(lambda u: is_service_name_ours(u.name), data)
        return {kres_id_from_service_name(u.name): convert(u.state) for u in our_data}
