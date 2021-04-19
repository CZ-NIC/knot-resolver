import asyncio
from typing import Type

from knot_resolver_manager.kresd_controller.base import BaseKresdController
from knot_resolver_manager.kresd_controller.supervisord import SupervisordKresdController
from knot_resolver_manager.kresd_controller.systemd import SystemdKresdController

# In this tuple, every supported controller should be listed. In the order of preference (preferred first)
_registered_controllers = (SystemdKresdController, SupervisordKresdController)


async def get_best_controller_implementation() -> Type[BaseKresdController]:
    # check all controllers concurrently
    res = await asyncio.gather(*(cont.is_controller_available() for cont in _registered_controllers))

    # take the first one on the list which is available
    for avail, controller in zip(res, _registered_controllers):
        if avail:
            return controller

    # or fail
    raise LookupError("Can't find any available service manager!")
