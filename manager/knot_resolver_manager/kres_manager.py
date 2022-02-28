import asyncio
import logging
import sys
from subprocess import SubprocessError
from typing import List, Optional

import knot_resolver_manager.kresd_controller
from knot_resolver_manager.compat.asyncio import create_task
from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.constants import WATCHDOG_INTERVAL
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessStatus,
    SubprocessType,
)
from knot_resolver_manager.utils.functional import Result
from knot_resolver_manager.utils.types import NoneType

from .datamodel import KresConfig

logger = logging.getLogger(__name__)


class KresManager:
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    def __init__(self, _i_know_what_i_am_doing: bool = False):
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
        self._watchdog_task: Optional["asyncio.Task[None]"] = None

    @staticmethod
    async def create(selected_controller: Optional[SubprocessController], config_store: ConfigStore) -> "KresManager":
        """
        Creates new instance of KresManager.
        """

        inst = KresManager(_i_know_what_i_am_doing=True)
        await inst._async_init(selected_controller, config_store)  # pylint: disable=protected-access
        return inst

    async def _async_init(self, selected_controller: Optional[SubprocessController], config_store: ConfigStore) -> None:
        if selected_controller is None:
            self._controller = await knot_resolver_manager.kresd_controller.get_best_controller_implementation(
                config_store.get()
            )
        else:
            self._controller = selected_controller
        await self._controller.initialize_controller(config_store.get())
        self._watchdog_task = create_task(self._watchdog())
        await self._load_system_state()

        # registering the function calls them immediately, therefore after this, the config is applied
        await config_store.register_verifier(self.validate_config)
        await config_store.register_on_change_callback(self.apply_config)

    async def _load_system_state(self) -> None:
        async with self._manager_lock:
            await self._collect_already_running_children()

    async def _spawn_new_worker(self, config: KresConfig) -> None:
        subprocess = await self._controller.create_subprocess(config, SubprocessType.KRESD)
        await subprocess.start()
        self._workers.append(subprocess)

    async def _stop_a_worker(self) -> None:
        if len(self._workers) == 0:
            raise IndexError("Can't stop a kresd when there are no running")

        subprocess = self._workers.pop()
        await subprocess.stop()

    async def _collect_already_running_children(self) -> None:
        for subp in await self._controller.get_all_running_instances():
            if subp.type == SubprocessType.KRESD:
                self._workers.append(subp)
            elif subp.type == SubprocessType.GC:
                assert self._gc is None
                self._gc = subp
            else:
                raise RuntimeError("unexpected subprocess type")

    async def _rolling_restart(self, new_config: KresConfig) -> None:
        for kresd in self._workers:
            await kresd.apply_new_config(new_config)

    async def _ensure_number_of_children(self, config: KresConfig, n: int) -> None:
        # kill children that are not needed
        while len(self._workers) > n:
            await self._stop_a_worker()

        # spawn new children if needed
        while len(self._workers) < n:
            await self._spawn_new_worker(config)

    def _is_gc_running(self) -> bool:
        return self._gc is not None

    async def _start_gc(self, config: KresConfig) -> None:
        subprocess = await self._controller.create_subprocess(config, SubprocessType.GC)
        await subprocess.start()
        self._gc = subprocess

    async def _stop_gc(self) -> None:
        assert self._gc is not None
        await self._gc.stop()
        self._gc = None

    async def validate_config(self, _old: KresConfig, new: KresConfig) -> Result[NoneType, str]:
        async with self._manager_lock:
            logger.debug("Testing the new config with a canary process")
            try:
                # technically, this has side effects of leaving a new process runnning
                # but it's practically not a problem, because
                #   if it keeps running, the config is valid and others will soon join as well
                #   if it crashes and the startup fails, then well, it's not running anymore... :)
                await self._spawn_new_worker(new)
            except SubprocessError:
                logger.error("kresd with the new config failed to start, rejecting config")
                return Result.err("Canary kresd instance failed to start. Config is invalid.")

            logger.debug("Canary process test passed.")
            return Result.ok(None)

    async def apply_config(self, config: KresConfig) -> None:
        async with self._manager_lock:
            logger.debug("Applying new config to all workers")
            await self._ensure_number_of_children(config, int(config.server.workers))
            await self._rolling_restart(config)

            if self._is_gc_running() != config.server.use_cache_gc:
                if config.server.use_cache_gc:
                    logger.debug("Starting cache GC")
                    await self._start_gc(config)
                else:
                    logger.debug("Stopping cache GC")
                    await self._stop_gc()

    async def stop(self):
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()  # cancel it
            try:
                await self._watchdog_task  # and let it really finish
            except asyncio.CancelledError:
                pass

        async with self._manager_lock:
            await self._ensure_number_of_children(KresConfig(), 0)
            if self._gc is not None:
                await self._stop_gc()
            await self._controller.shutdown_controller()

    async def _instability_handler(self) -> None:
        logger.error(
            "Instability detected. Something is wrong, no idea how to react." " Performing suicide. See you later!"
        )
        sys.exit(1)

    async def _watchdog(self) -> None:
        while True:
            await asyncio.sleep(WATCHDOG_INTERVAL)

            try:
                # gather current state
                async with self._manager_lock:
                    detected_subprocesses = await self._controller.get_subprocess_status()
                expected_ids = [x.id for x in self._workers]
                if self._gc:
                    expected_ids.append(self._gc.id)
                invoke_callback = False

                for eid in expected_ids:
                    if eid not in detected_subprocesses:
                        logger.error("Expected to find subprocess with id '%s' in the system, but did not.", eid)
                        invoke_callback = True
                        continue

                    if detected_subprocesses[eid] is SubprocessStatus.FAILED:
                        logger.error("Subprocess '%s' is failed.", eid)
                        invoke_callback = True
                        continue

                    if detected_subprocesses[eid] is SubprocessStatus.UNKNOWN:
                        logger.warning("Subprocess '%s' is in unknown state!", eid)

            except asyncio.CancelledError:
                raise
            except BaseException:
                invoke_callback = True
                logger.error("Knot Resolver watchdog failed with an unexpected exception.", exc_info=True)

            if invoke_callback:
                await self._instability_handler()
