import asyncio
import logging
import sys
from asyncio.futures import Future
from subprocess import SubprocessError
from typing import List, Optional

import knot_resolver_manager.kresd_controller
from knot_resolver_manager import kres_id
from knot_resolver_manager.compat.asyncio import create_task
from knot_resolver_manager.constants import KRESD_CONFIG_FILE, WATCHDOG_INTERVAL
from knot_resolver_manager.exceptions import KresdManagerException
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.utils.async_utils import writefile
from knot_resolver_manager.utils.parsing import ParsedTree

from .datamodel import KresConfig

logger = logging.getLogger(__name__)


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    @staticmethod
    async def create(selected_controller: Optional[SubprocessController], config: KresConfig) -> "KresManager":
        """
        Creates new instance of KresManager.
        """

        inst = KresManager(config, _i_know_what_i_am_doing=True)
        await inst._async_init(selected_controller, config)  # pylint: disable=protected-access
        return inst

    async def _async_init(self, selected_controller: Optional[SubprocessController], config: KresConfig):
        if selected_controller is None:
            self._controller = await knot_resolver_manager.kresd_controller.get_best_controller_implementation()
        else:
            self._controller = selected_controller
        await self._controller.initialize_controller()
        self._watchdog_task = create_task(self._watchdog())
        await self.load_system_state()
        await self.apply_config(config)

    def __init__(self, config: KresConfig, _i_know_what_i_am_doing: bool = False):
        if not _i_know_what_i_am_doing:
            logger.error(
                "Trying to create an instance of KresManager using normal constructor. Please use "
                "`KresManager.get_instance()` instead"
            )
            sys.exit(1)

        self._workers: List[Subprocess] = []
        self._gc: Optional[Subprocess] = None
        self._manager_lock = asyncio.Lock()
        self._controller: SubprocessController
        self._last_used_config_raw: Optional[ParsedTree]
        self._last_used_config: KresConfig = config
        self._watchdog_task: Optional["Future[None]"] = None

    async def load_system_state(self):
        async with self._manager_lock:
            await self._collect_already_running_children()

    async def _spawn_new_worker(self):
        subprocess = await self._controller.create_subprocess(SubprocessType.KRESD, kres_id.alloc())
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
        subprocess = await self._controller.create_subprocess(SubprocessType.GC, kres_id.alloc())
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
                raise KresdManagerException("Canary kresd instance failed. Config is invalid.")

            logger.debug("Canary process test passed, Applying new config to all workers")
            self._last_used_config = config
            await self._ensure_number_of_children(config.server.workers)
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

        if self._watchdog_task is not None:
            self._watchdog_task.cancel()

    def get_last_used_config(self) -> KresConfig:
        return self._last_used_config

    async def _instability_handler(self) -> None:
        logger.error(
            "Instability callback invoked. Something is wrong, no idea how to react."
            " Performing suicide. See you later!"
        )
        sys.exit(1)

    async def _watchdog(self) -> None:
        while True:
            await asyncio.sleep(WATCHDOG_INTERVAL)

            # gather current state
            units = {u.id: u for u in await self._controller.get_subprocess_info()}
            worker_ids = [x.id for x in self._workers]
            invoke_callback = False

            for w in worker_ids:
                if w not in units:
                    logger.error("Expected to find subprocess with id '%s' in the system, but did not.", w)
                    invoke_callback = True
                    continue

                if units[w].status is SubprocessStatus.FAILED:
                    logger.error("Subprocess '%s' is failed.", w)
                    invoke_callback = True
                    continue

                if units[w].status is SubprocessStatus.UNKNOWN:
                    logger.warning("Subprocess '%s' is in unknown state!", w)

            if invoke_callback:
                await self._instability_handler()
