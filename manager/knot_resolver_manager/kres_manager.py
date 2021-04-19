import asyncio
from typing import Any, List, Type

from knot_resolver_manager.kresd_controller import BaseKresdController, get_best_controller_implementation

from . import configuration
from .datamodel import KresConfig


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    @classmethod
    async def create(cls: Type["KresManager"], *args: Any, **kwargs: Any) -> "KresManager":
        obj = cls()
        await obj._async_init(*args, **kwargs)  # pylint: disable=protected-access
        return obj

    async def _async_init(self):
        self._controller = await get_best_controller_implementation()
        await self._controller.initialize_controller()
        await self.load_system_state()

    def __init__(self):
        self._children: List[BaseKresdController] = []
        self._children_lock = asyncio.Lock()
        self._controller: Type[BaseKresdController]

    async def load_system_state(self):
        async with self._children_lock:
            await self._collect_already_running_children()

    async def _spawn_new_child(self):
        kresd = self._controller()
        await kresd.start()
        self._children.append(kresd)

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
        # FIXME: this code is blocking!!!
        lua_config = await configuration.render_lua(config)
        with open("/etc/knot-resolver/kresd.conf", "w") as f:
            f.write(lua_config)

    async def apply_config(self, config: KresConfig):
        async with self._children_lock:
            await self._write_config(config)
            await self._ensure_number_of_children(config.server.get_instances())
            await self._rolling_restart()
