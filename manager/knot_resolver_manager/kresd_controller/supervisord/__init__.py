import logging
from typing import Iterable

from knot_resolver_manager.kresd_controller.base import BaseKresdController

from .config import (
    SupervisordConfig,
    is_supervisord_available,
    is_supervisord_running,
    list_ids_from_existing_config,
    restart,
    start_supervisord,
    update_config,
)

logger = logging.getLogger(__name__)


class SupervisordKresdController(BaseKresdController):
    _config = SupervisordConfig([])

    async def is_running(self) -> bool:
        return self.id in SupervisordKresdController._config.instances

    async def start(self):
        # note: O(n) test, but the number of instances will be very small
        if self.id in SupervisordKresdController._config.instances:
            raise RuntimeError("Can't start an instance with the same ID as already started instance")

        SupervisordKresdController._config.instances.append(self.id)
        await update_config(SupervisordKresdController._config)

    async def stop(self):
        # note: O(n) test, but the number of instances will be very small
        if self.id not in SupervisordKresdController._config.instances:
            raise RuntimeError("Can't stop an instance that is not started")

        SupervisordKresdController._config.instances.remove(self.id)
        await update_config(SupervisordKresdController._config)

    async def restart(self):
        # note: O(n) test, but the number of instances will be very small
        if self.id not in SupervisordKresdController._config.instances:
            raise RuntimeError("Can't restart an instance that is not started")

        await restart(self.id)

    @staticmethod
    async def is_controller_available() -> bool:
        return await is_supervisord_available()

    @staticmethod
    async def get_all_running_instances() -> Iterable["BaseKresdController"]:
        running = await is_supervisord_running()
        if running:
            ids = await list_ids_from_existing_config()
            return [SupervisordKresdController(id) for id in ids]
        else:
            return []

    @staticmethod
    async def initialize_controller() -> None:
        if not await is_supervisord_running():
            await start_supervisord(SupervisordKresdController._config)
