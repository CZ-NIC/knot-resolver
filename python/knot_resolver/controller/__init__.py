"""
This file contains autodetection logic for available subprocess controllers. Because we have to catch errors
from imports, they are located in functions which are invoked at the end of this file.

We supported multiple subprocess controllers while developing it. It now all converged onto just supervisord.
The interface however remains so that different controllers can be added in the future.
"""

# pylint: disable=import-outside-toplevel

import asyncio
import logging
from typing import List, Optional

from knot_resolver.controller.interface import SubprocessController
from knot_resolver.datamodel.config_schema import KresConfig

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
        from knot_resolver.controller.supervisord import SupervisordSubprocessController

        _registered_controllers.append(SupervisordSubprocessController())
    except ImportError:
        logger.error("Failed to import modules related to supervisord service manager", exc_info=True)


async def get_best_controller_implementation(config: KresConfig) -> SubprocessController:
    logger.info("Starting service manager auto-selection...")

    if len(_registered_controllers) == 0:
        logger.error("No controllers are available! Did you install all dependencies?")
        raise LookupError("No service managers available!")

    # check all controllers concurrently
    res = await asyncio.gather(*(cont.is_controller_available(config) for cont in _registered_controllers))
    logger.info(
        "Available subprocess controllers are %s",
        str(tuple((str(c) for r, c in zip(res, _registered_controllers) if r))),
    )

    # take the first one on the list which is available
    for avail, controller in zip(res, _registered_controllers):
        if avail:
            logger.info("Selected controller '%s'", str(controller))
            return controller

    # or fail
    raise LookupError("Can't find any available service manager!")


def list_controller_names() -> List[str]:
    """
    Returns a list of names of registered controllers. The listed controllers are not necessarly functional.
    """

    return [str(controller) for controller in sorted(_registered_controllers, key=str)]


async def get_controller_by_name(config: KresConfig, name: str) -> SubprocessController:
    logger.debug("Subprocess controller selected manualy by the user, testing feasibility...")

    controller: Optional[SubprocessController] = None
    for c in sorted(_registered_controllers, key=str):
        if str(c).startswith(name):
            if str(c) != name:
                logger.debug("Assuming '%s' is a shortcut for '%s'", name, str(c))
            controller = c
            break

    if controller is None:
        logger.error("Subprocess controller with name '%s' was not found", name)
        raise LookupError(f"No subprocess controller named '{name}' found")

    if await controller.is_controller_available(config):
        logger.info("Selected controller '%s'", str(controller))
        return controller
    raise LookupError("The selected subprocess controller is not available for use on this system.")


# run the imports on module load
try_supervisord()
