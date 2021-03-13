import asyncio
from uuid import uuid4
from typing import List, Optional
from strictyaml.representation import YAML

from . import compat
from . import systemd


class Kresd:
    def __init__(self, kresd_id: Optional[str] = None):
        self._lock = asyncio.Lock()
        self._id: str = kresd_id or str(uuid4())

        # if we got existing id, mark for restart
        self._needs_restart: bool = id is not None

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def start(self):
        await compat.asyncio_to_thread(systemd.start_unit, f"kresd@{self._id}.service")

    async def stop(self):
        await compat.asyncio_to_thread(systemd.stop_unit, f"kresd@{self._id}.service")

    async def restart(self):
        await compat.asyncio_to_thread(
            systemd.restart_unit, f"kresd@{self._id}.service"
        )

    def mark_for_restart(self):
        self._needs_restart = True


class KresdManager:
    def __init__(self):
        self._children: List[Kresd] = []
        self._children_lock = asyncio.Lock()

    async def load_system_state(self):
        async with self._children_lock:
            await self._collect_already_running_children()

    async def _spawn_new_child(self):
        kresd = Kresd()
        await kresd.start()
        self._children.append(kresd)

    async def _stop_a_child(self):
        if len(self._children) == 0:
            raise IndexError("Can't stop a kresd when there are no running")

        kresd = self._children.pop()
        await kresd.stop()

    async def _collect_already_running_children(self):
        units = await compat.asyncio_to_thread(systemd.list_units)
        for unit in units:
            u: str = unit
            if u.startswith("kresd@") and u.endswith(".service"):
                iden = u.replace("kresd@", "").replace(".service", "")
                self._children.append(Kresd(kresd_id=iden))

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

    async def _write_config(self, config: YAML):
        # FIXME: this code is blocking!!!
        with open("/etc/knot-resolver/kresd.conf", "w") as f:
            f.write(config["lua_config"].text)

    async def apply_config(self, config: YAML):
        async with self._children_lock:
            await self._write_config(config)
            await self._ensure_number_of_children(config["num_workers"])
            await self._rolling_restart()
