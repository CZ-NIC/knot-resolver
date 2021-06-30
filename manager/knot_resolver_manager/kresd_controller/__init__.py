"""
This file contains autodetection logic for available subprocess controllers. Because we have to catch errors
from imports, you can not see a simple list, but it's more complicated.
"""
# pylint: disable=import-outside-toplevel

import asyncio
import logging
from typing import List

from knot_resolver_manager.kresd_controller.interface import SubprocessController

logger = logging.getLogger(__name__)

"""
List of all subprocess controllers that are available in order of priority.
It is filled dynamically based on available modules that do not fail to import.
"""
_registered_controllers: List[SubprocessController] = []


def try_supervisord():
    """
    Attempt to load supervisord controllers.
    """
    try:
        from knot_resolver_manager.kresd_controller.supervisord import SupervisordSubprocessController

        _registered_controllers.append(SupervisordSubprocessController())
    except ImportError:
        logger.info("Failed to import modules related to supervisord service manager")


def try_systemd():
    """
    Attempt to load systemd controllers.
    """
    try:
        from knot_resolver_manager.kresd_controller.systemd import SystemdSubprocessController, SystemdPersistanceType

        from knot_resolver_manager.kresd_controller.systemd.dbus_api import SystemdType

        _registered_controllers.extend(
            [
                SystemdSubprocessController(SystemdType.SYSTEM),
                SystemdSubprocessController(SystemdType.SESSION),
                SystemdSubprocessController(SystemdType.SESSION, SystemdPersistanceType.TRANSIENT),
            ]
        )
    except ImportError:
        logger.info("Failed to import modules related to systemd service manager")


async def get_best_controller_implementation() -> SubprocessController:
    logger.debug("Starting service manager auto-selection...")

    if len(_registered_controllers) == 0:
        logger.error("No controllers are available! Did you install all dependencies?")
        raise LookupError("No service managers available!")

    # check all controllers concurrently
    res = await asyncio.gather(*(cont.is_controller_available() for cont in _registered_controllers))

    # take the first one on the list which is available
    for avail, controller in zip(res, _registered_controllers):
        if avail:
            logger.info("Selected controller '%s'", str(controller))
            return controller

    # or fail
    raise LookupError("Can't find any available service manager!")


# run the imports on module load
try_systemd()
try_supervisord()
