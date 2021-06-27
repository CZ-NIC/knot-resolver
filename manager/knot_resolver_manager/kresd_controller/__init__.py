import asyncio
import logging
from typing import Tuple

from knot_resolver_manager.kresd_controller.interface import SubprocessController
from knot_resolver_manager.kresd_controller.supervisord import SupervisordSubprocessController
from knot_resolver_manager.kresd_controller.systemd import SystemdSubprocessController
from knot_resolver_manager.kresd_controller.systemd.dbus_api import SystemdType

# In this tuple, every supported controller should be listed. In the order of preference (preferred first)
_registered_controllers: Tuple[SubprocessController, ...] = (
    SystemdSubprocessController(SystemdType.SESSION),
    SystemdSubprocessController(SystemdType.SYSTEM),
    SupervisordSubprocessController(),
)

logger = logging.getLogger(__name__)


async def get_best_controller_implementation() -> SubprocessController:
    # check all controllers concurrently
    res = await asyncio.gather(*(cont.is_controller_available() for cont in _registered_controllers))

    # take the first one on the list which is available
    for avail, controller in zip(res, _registered_controllers):
        if avail:
            logger.info("Selected controller '%s'", str(controller))
            return controller

    # or fail
    raise LookupError("Can't find any available service manager!")
