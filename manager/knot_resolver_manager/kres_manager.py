import asyncio
import logging
import sys
import time
from subprocess import SubprocessError
from typing import List, NoReturn, Optional

import knot_resolver_manager.kresd_controller
from knot_resolver_manager.compat.asyncio import create_task
from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.constants import (
    FIX_COUNTER_DECREASE_INTERVAL_SEC,
    MANAGER_FIX_ATTEMPT_MAX_COUNTER,
    WATCHDOG_INTERVAL,
)
from knot_resolver_manager.exceptions import SubprocessControllerException
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


class _FixCounter:
    def __init__(self) -> None:
        self._counter = 0
        self._timestamp = time.time()

    def increase(self) -> None:
        self._counter += 1
        self._timestamp = time.time()

    def try_decrease(self) -> None:
        if time.time() - self._timestamp > FIX_COUNTER_DECREASE_INTERVAL_SEC:
            if self._counter > 0:
                logger.info(
                    f"Enough time has passed since last detected instability, decreasing fix attempt counter to {self._counter}"
                )
                self._counter -= 1
                self._timestamp = time.time()

    def __str__(self) -> str:
        return str(self._counter)

    def is_too_high(self) -> bool:
        return self._counter > MANAGER_FIX_ATTEMPT_MAX_COUNTER


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
        self._fix_counter: _FixCounter = _FixCounter()
        self._config_store: ConfigStore

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
        self._config_store = config_store
        await self._controller.initialize_controller(config_store.get())
        self._watchdog_task = create_task(self._watchdog())
        await self._collect_already_running_workers()

        # registering the function calls them immediately, therefore after this, the config is applied
        await config_store.register_verifier(self.validate_config)
        await config_store.register_on_change_callback(self.apply_config)

    async def _spawn_new_worker(self, config: KresConfig) -> None:
        subprocess = await self._controller.create_subprocess(config, SubprocessType.KRESD)
        await subprocess.start()
        self._workers.append(subprocess)

    async def _stop_a_worker(self) -> None:
        if len(self._workers) == 0:
            raise IndexError("Can't stop a kresd when there are no running")

        subprocess = self._workers.pop()
        await subprocess.stop()

    async def _collect_already_running_workers(self) -> None:
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

    async def _reload_system_state(self) -> None:
        async with self._manager_lock:
            self._workers = []
            self._gc = None
            await self._collect_already_running_workers()

    async def apply_config(self, config: KresConfig, _noretry: bool = False) -> None:
        try:
            async with self._manager_lock:
                logger.debug("Applying config to all workers")
                await self._ensure_number_of_children(config, int(config.server.workers))
                await self._rolling_restart(config)

                if self._is_gc_running() != config.server.use_cache_gc:
                    if config.server.use_cache_gc:
                        logger.debug("Starting cache GC")
                        await self._start_gc(config)
                    else:
                        logger.debug("Stopping cache GC")
                        await self._stop_gc()
        except SubprocessControllerException as e:
            if _noretry:
                raise
            elif self._fix_counter.is_too_high():
                logger.error(f"Failed to apply config: {e}")
                logger.error("There have already been problems recently, refusing to try to fix it.")
                await self.forced_shutdown()  # possible improvement - the person who requested this change won't get a response this way
            else:
                logger.error(f"Failed to apply config: {e}")
                logger.warning("Reloading system state and trying again.")
                self._fix_counter.increase()
                await self._reload_system_state()
                await self.apply_config(config, _noretry=True)

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

    async def forced_shutdown(self) -> NoReturn:
        logger.warning("Collecting all remaining workers...")
        await self._reload_system_state()

        logger.warning("Stopping all workers...")
        await self.stop()
        logger.warning(
            "All workers stopped. Terminating. You might see an exception stack trace at the end of the log."
        )
        sys.exit(1)

    async def _instability_handler(self) -> None:
        if self._fix_counter.is_too_high():
            logger.error(
                "Already attempted to many times to fix system state. Refusing to try again and shutting down."
            )
            await self.forced_shutdown()

        try:
            logger.warning("Instability detected. Dropping known list of workers and reloading it from the system.")
            self._fix_counter.increase()
            await self._reload_system_state()
            logger.warning("Workers reloaded. Applying old config....")
            await self.apply_config(self._config_store.get(), _noretry=True)
            logger.warning(f"System stability hopefully renewed. Fix attempt counter is currently {self._fix_counter}")
        except BaseException:
            logger.error("Failed attempting to fix an error. Forcefully shutting down.", exc_info=True)
            await self.forced_shutdown()

    async def _watchdog(self) -> None:
        while True:
            await asyncio.sleep(WATCHDOG_INTERVAL)

            self._fix_counter.try_decrease()

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
                try:
                    await self._instability_handler()
                except Exception:
                    logger.error("Watchdog failed while invoking instability callback", exc_info=True)
                    logger.error("Violently terminating!")
                    sys.exit(1)
