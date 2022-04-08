import asyncio
import logging
import os
import re
from typing import Dict, Iterable, List, Optional, Union

from knot_resolver_manager import compat
from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kresd_controller.interface import (
    KresID,
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.kresd_controller.systemd.dbus_api import (
    SystemdType,
    Unit,
    is_unit_failed,
    list_our_slice_processes,
    list_units,
    reset_failed_unit,
    restart_unit,
    start_slice,
    start_transient_kresd_unit,
    stop_slice,
    stop_unit,
)
from knot_resolver_manager.utils import phantom_use
from knot_resolver_manager.utils.async_utils import call

logger = logging.getLogger(__name__)


GC_SERVICE_BASE_NAME = "kres_cache_gc.service"
KRESD_SERVICE_BASE_PATTERN = re.compile(r"^kresd_([0-9]+).service$")


def _is_service_name_ours(name: str) -> bool:
    is_ours = name == GC_SERVICE_BASE_NAME
    is_ours |= bool(KRESD_SERVICE_BASE_PATTERN.match(name))
    return is_ours


class SystemdKresID(KresID):
    @staticmethod
    def from_string(val: str) -> "SystemdKresID":
        if val == GC_SERVICE_BASE_NAME:
            return SystemdKresID.new(SubprocessType.GC, -1)
        else:
            kid = KRESD_SERVICE_BASE_PATTERN.search(val)
            if kid:
                return SystemdKresID.new(SubprocessType.KRESD, int(kid.groups()[0]))
            else:
                raise RuntimeError("Trying to parse systemd service name which does not match our expectations")

    def __str__(self) -> str:
        if self.subprocess_type is SubprocessType.GC:
            return GC_SERVICE_BASE_NAME
        elif self.subprocess_type is SubprocessType.KRESD:
            return f"kresd_{self._id}.service"
        else:
            raise RuntimeError(f"Unexpected subprocess type {self.subprocess_type}")


class SystemdSubprocess(Subprocess):
    def __init__(self, config: KresConfig, systemd_type: SystemdType, id_base: Union[SubprocessType, KresID]):
        if isinstance(id_base, SubprocessType):
            if id_base is SubprocessType.GC:
                super().__init__(config, SystemdKresID.new(id_base, -1))
            else:
                super().__init__(config, SystemdKresID.alloc(id_base))
        else:
            super().__init__(config, id_base)
        self._systemd_type = systemd_type

    async def _start(self):
        await compat.asyncio.to_thread(start_transient_kresd_unit, self._config, self._systemd_type, self.id)

    async def _stop(self):
        await compat.asyncio.to_thread(stop_unit, self._systemd_type, str(self.id))

    async def _restart(self):
        await compat.asyncio.to_thread(restart_unit, self._systemd_type, str(self.id))


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

        units = await compat.asyncio.to_thread(list_our_slice_processes, self._controller_config, self._systemd_type)

        async def load(name: str) -> Optional[SystemdSubprocess]:
            assert self._controller_config is not None

            if _is_service_name_ours(name):
                failed = await to_thread(is_unit_failed, self._systemd_type, name)
                if failed:
                    # if a unit is failed, remove it from the system by reseting its state
                    logger.warning("Unit '%s' is already failed, resetting its state and ignoring it", name)
                    await compat.asyncio.to_thread(reset_failed_unit, self._systemd_type, name)
                    return None

                return SystemdSubprocess(
                    self._controller_config,
                    self._systemd_type,
                    SystemdKresID.from_string(name),
                )
            else:
                return None

        subprocesses = await asyncio.gather(*[load(name) for name in units])
        return filter(lambda x: x is not None, subprocesses)  # type: ignore

    async def initialize_controller(self, config: KresConfig) -> None:
        self._controller_config = config
        try:
            await to_thread(start_slice, self._controller_config, self._systemd_type)
        except SubprocessControllerException as e:
            logger.warning(
                f"Failed to create systemd slice for our subprocesses: '{e}'. There is/was a manager running with the same ID."
            )

    async def shutdown_controller(self) -> None:
        await to_thread(stop_slice, self._controller_config, self._systemd_type)

    async def create_subprocess(self, subprocess_config: KresConfig, subprocess_type: SubprocessType) -> Subprocess:
        assert self._controller_config is not None
        return SystemdSubprocess(subprocess_config, self._systemd_type, subprocess_type)

    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        assert self._controller_config is not None

        def convert(val: str) -> SubprocessStatus:
            status_lookup_table = {"failed": SubprocessStatus.FAILED, "running": SubprocessStatus.RUNNING}
            if val in status_lookup_table:
                return status_lookup_table[val]
            else:
                return SubprocessStatus.UNKNOWN

        data: List[Unit] = await to_thread(list_units, self._systemd_type)

        our_data = filter(lambda u: _is_service_name_ours(u.name), data)
        return {SystemdKresID.from_string(u.name): convert(u.state) for u in our_data}
