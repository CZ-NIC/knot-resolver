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
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.utils import DataValidationException
from knot_resolver_manager.utils.async_utils import writefile

from .datamodel import KresConfig, KresConfigStrict

logger = logging.getLogger(__name__)


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    _instance_lock = asyncio.Lock()
    _instance: Optional["KresManager"] = None

    @staticmethod
    async def create_instance(selected_controller: Optional[SubprocessController]) -> "KresManager":
        """
        Creates new singleton instance of KresManager. Can be called only once. Afterwards, use
        `KresManager.get_instance()` to obtain the already existing instance
        """

        assert KresManager._instance is None

        async with KresManager._instance_lock:
            # trying to create, but racing and somebody already did it
            if KresManager._instance is not None:
                raise AssertionError("Must NOT call `create_instance` multiple times - race detected!")

            # create it for real
            inst = KresManager(_i_know_what_i_am_doing=True)
            await inst._async_init(selected_controller)  # pylint: disable=protected-access
            KresManager._instance = inst
            return inst

    @staticmethod
    def get_instance() -> "KresManager":
        """
        Obtain reference to the singleton instance of this class. If you want to create an instance,
        use `create_instance()`
        """
        assert KresManager._instance is not None
        return KresManager._instance

    async def _async_init(self, selected_controller: Optional[SubprocessController]):
        if selected_controller is None:
            self._controller = await knot_resolver_manager.kresd_controller.get_best_controller_implementation()
        else:
            self._controller = selected_controller
        await self._controller.initialize_controller()
        self._watchdog_task = create_task(self._watchdog())
        await self.load_system_state()

    def __init__(self, _i_know_what_i_am_doing: bool = False):
        if not _i_know_what_i_am_doing:
            logger.error(
                "Trying to create an instance of KresManager using normal contructor. Please use "
                "`KresManager.get_instance()` instead"
            )
            sys.exit(1)

        self._workers: List[Subprocess] = []
        self._gc: Optional[Subprocess] = None
        self._manager_lock = asyncio.Lock()
        self._controller: SubprocessController
        self._last_used_config: Optional[KresConfig] = None
        self._last_used_config_strict: Optional[KresConfigStrict] = None
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

    async def _write_config(self, config_strict: KresConfigStrict):
        lua_config = config_strict.render_lua()
        await writefile(KRESD_CONFIG_FILE, lua_config)

    async def apply_config(self, config: KresConfig):
        async with self._manager_lock:
            logger.debug("Validating configuration...")
            config_strict = KresConfigStrict(config)

            logger.debug("Writing new config to file...")
            await self._write_config(config_strict)

            logger.debug("Testing the new config with a canary process")
            try:
                await self._spawn_new_worker()
            except SubprocessError:
                logger.error("kresd with the new config failed to start, rejecting config")
                last = self.get_last_used_config_strict()
                if last is not None:
                    await self._write_config(last)
                raise DataValidationException("Canary kresd instance failed. Config is invalid.")

            logger.debug("Canary process test passed, Applying new config to all workers")
            self._last_used_config = config
            self._last_used_config_strict = config_strict
            await self._ensure_number_of_children(config_strict.server.workers)
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

    def get_last_used_config(self) -> Optional[KresConfig]:
        return self._last_used_config

    def get_last_used_config_strict(self) -> Optional[KresConfigStrict]:
        return self._last_used_config_strict

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
