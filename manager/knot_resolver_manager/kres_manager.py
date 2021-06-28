import asyncio
from typing import List, Optional, Type
from uuid import uuid4

from knot_resolver_manager.constants import KRESD_CONFIG_FILE
from knot_resolver_manager.kresd_controller import get_best_controller_implementation
from knot_resolver_manager.kresd_controller.interface import Subprocess, SubprocessController, SubprocessType
from knot_resolver_manager.utils.async_utils import writefile

from .datamodel import KresConfig


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    @classmethod
    async def create(cls: Type["KresManager"]) -> "KresManager":
        obj = cls()
        await obj._async_init()  # pylint: disable=protected-access
        return obj

    async def _async_init(self):
        self._controller = await get_best_controller_implementation()
        await self._controller.initialize_controller()
        await self.load_system_state()

    def __init__(self):
        self._children: List[Subprocess] = []
        self._manager_lock = asyncio.Lock()
        self._controller: SubprocessController
        self._last_used_config: Optional[KresConfig] = None

    async def load_system_state(self):
        async with self._manager_lock:
            await self._collect_already_running_children()

    async def _spawn_new_child(self):
        subprocess = await self._controller.create_subprocess(SubprocessType.KRESD, str(uuid4()))
        await subprocess.start()
        self._children.append(subprocess)

    async def _stop_a_child(self):
        if len(self._children) == 0:
            raise IndexError("Can't stop a kresd when there are no running")

        kresd = self._children.pop()
        await kresd.stop()

    async def _collect_already_running_children(self):
        self._children.extend(await self._controller.get_all_running_instances())

    async def _rolling_restart(self):
        for kresd in self._children:
            await kresd.restart()
            await asyncio.sleep(1)

    async def _ensure_number_of_children(self, n: int):
        # kill children that are not needed
        while len(self._children) > n:
            await self._stop_a_child()

        # spawn new children if needed
        while len(self._children) < n:
            await self._spawn_new_child()

    async def _write_config(self, config: KresConfig):
        lua_config = config.render_lua()
        await writefile(KRESD_CONFIG_FILE, lua_config)

    async def apply_config(self, config: KresConfig):
        async with self._manager_lock:
            await self._write_config(config)
            self._last_used_config = config
            await self._ensure_number_of_children(config.server.get_instances())
            await self._rolling_restart()

    async def stop(self):
        async with self._manager_lock:
            await self._ensure_number_of_children(0)
            await self._controller.shutdown_controller()

    def get_last_used_config(self) -> Optional[KresConfig]:
        return self._last_used_config
