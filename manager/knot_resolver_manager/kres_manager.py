import asyncio
import itertools
import logging
import weakref
from subprocess import SubprocessError
from typing import List, Optional, Type

from knot_resolver_manager.constants import KRESD_CONFIG_FILE
from knot_resolver_manager.exceptions import ValidationException
from knot_resolver_manager.kresd_controller import get_best_controller_implementation
from knot_resolver_manager.kresd_controller.interface import Subprocess, SubprocessController, SubprocessType
from knot_resolver_manager.utils.async_utils import writefile

from .datamodel import KresConfig

logger = logging.getLogger(__name__)


class _PrettyID:
    """
    ID object. Effectively only a wrapper around an int, so that the references
    behave normally (bypassing integer interning and other optimizations)
    """

    def __init__(self, n: int):
        self._id = n

    def __str__(self):
        return str(self._id)

    def __hash__(self) -> int:
        return self._id

    def __eq__(self, o: object) -> bool:
        return isinstance(o, _PrettyID) and self._id == o._id


class _PrettyIDAllocator:
    """
    Pretty numeric ID allocator. Keeps weak refences to the IDs it has
    allocated. The IDs get recycled once the previously allocated ID
    objects get garbage collected
    """

    def __init__(self):
        self._used: "weakref.WeakSet[_PrettyID]" = weakref.WeakSet()

    def alloc(self) -> _PrettyID:
        for i in itertools.count(start=1):
            val = _PrettyID(i)
            if val not in self._used:
                self._used.add(val)
                return val

        raise RuntimeError("Reached an end of an infinite loop. How?")


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    @classmethod
    async def create(cls: Type["KresManager"], controller: Optional[SubprocessController]) -> "KresManager":
        obj = cls()
        await obj._async_init(controller)  # pylint: disable=protected-access
        return obj

    async def _async_init(self, selected_controller: Optional[SubprocessController]):
        if selected_controller is None:
            self._controller = await get_best_controller_implementation()
        else:
            self._controller = selected_controller
        await self._controller.initialize_controller()
        await self.load_system_state()

    def __init__(self):
        self._workers: List[Subprocess] = []
        self._gc: Optional[Subprocess] = None
        self._manager_lock = asyncio.Lock()
        self._controller: SubprocessController
        self._last_used_config: Optional[KresConfig] = None
        self._id_allocator = _PrettyIDAllocator()

    async def load_system_state(self):
        async with self._manager_lock:
            await self._collect_already_running_children()

    async def _spawn_new_worker(self):
        subprocess = await self._controller.create_subprocess(SubprocessType.KRESD, self._id_allocator.alloc())
        await subprocess.start()
        self._workers.append(subprocess)

    async def _stop_a_worker(self):
        if len(self._workers) == 0:
            raise IndexError("Can't stop a kresd when there are no running")

        kresd = self._workers.pop()
        await kresd.stop()

    async def _collect_already_running_children(self):
        for subp in await self._controller.get_all_running_instances():
            if subp.type == SubprocessType.KRESD:
                self._workers.append(subp)
            elif subp.type == SubprocessType.GC:
                assert self._gc is None
                self._gc = subp
            else:
                raise RuntimeError("unexpected subprocess type")

    async def _rolling_restart(self):
        for kresd in self._workers:
            await kresd.restart()
            await asyncio.sleep(1)

    async def _ensure_number_of_children(self, n: int):
        # kill children that are not needed
        while len(self._workers) > n:
            await self._stop_a_worker()

        # spawn new children if needed
        while len(self._workers) < n:
            await self._spawn_new_worker()

    def _is_gc_running(self) -> bool:
        return self._gc is not None

    async def _start_gc(self):
        subprocess = await self._controller.create_subprocess(SubprocessType.GC, "gc")
        await subprocess.start()
        self._gc = subprocess

    async def _stop_gc(self):
        assert self._gc is not None
        await self._gc.stop()
        self._gc = None

    async def _write_config(self, config: KresConfig):
        lua_config = config.render_lua()
        await writefile(KRESD_CONFIG_FILE, lua_config)

    async def apply_config(self, config: KresConfig):
        async with self._manager_lock:
            logger.debug("Writing new config to file...")
            await self._write_config(config)

            logger.debug("Testing the new config with a canary process")
            try:
                await self._spawn_new_worker()
            except SubprocessError:
                logger.error("kresd with the new config failed to start, rejecting config")
                last = self.get_last_used_config()
                if last is not None:
                    await self._write_config(last)
                raise ValidationException("Canary kresd instance failed. Config is invalid.")

            logger.debug("Canary process test passed, Applying new config to all workers")
            self._last_used_config = config
            await self._ensure_number_of_children(config.server.get_instances())
            await self._rolling_restart()

            if self._is_gc_running() != config.server.use_cache_gc:
                if config.server.use_cache_gc:
                    logger.debug("Starting cache GC")
                    await self._start_gc()
                else:
                    logger.debug("Stopping cache GC")
                    await self._stop_gc()

    async def stop(self):
        async with self._manager_lock:
            await self._ensure_number_of_children(0)
            await self._controller.shutdown_controller()

    def get_last_used_config(self) -> Optional[KresConfig]:
        return self._last_used_config
