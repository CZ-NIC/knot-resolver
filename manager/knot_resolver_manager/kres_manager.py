import asyncio
import logging
import sys
import time
from subprocess import SubprocessError
from typing import Callable, List, Optional

from knot_resolver_manager.compat.asyncio import create_task
from knot_resolver_manager.config_store import ConfigStore, only_on_real_changes
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
from knot_resolver_manager.kresd_controller.registered_workers import (
    command_registered_workers,
    get_registered_workers_kresids,
)
from knot_resolver_manager.utils.functional import Result
from knot_resolver_manager.utils.modeling.types import NoneType

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
        return self._counter >= MANAGER_FIX_ATTEMPT_MAX_COUNTER


async def _deny_max_worker_changes(config_old: KresConfig, config_new: KresConfig) -> Result[None, str]:
    if config_old.max_workers != config_new.max_workers:
        return Result.err("Changing manager's `rundir` during runtime is not allowed.")

    return Result.ok(None)


class KresManager:  # pylint: disable=too-many-instance-attributes
    """
    Core of the whole operation. Orchestrates individual instances under some
    service manager like systemd.

    Instantiate with `KresManager.create()`, not with the usual constructor!
    """

    def __init__(self, shutdown_trigger: Callable[[int], None], _i_know_what_i_am_doing: bool = False):
        if not _i_know_what_i_am_doing:
            logger.error(
                "Trying to create an instance of KresManager using normal constructor. Please use "
                "`KresManager.get_instance()` instead"
            )
            assert False

        self._workers: List[Subprocess] = []
        self._gc: Optional[Subprocess] = None
        self._policy_loader: Optional[Subprocess] = None
        self._manager_lock = asyncio.Lock()
        self._controller: SubprocessController
        self._watchdog_task: Optional["asyncio.Task[None]"] = None
        self._fix_counter: _FixCounter = _FixCounter()
        self._config_store: ConfigStore
        self._shutdown_trigger: Callable[[int], None] = shutdown_trigger

    @staticmethod
    async def create(
        subprocess_controller: SubprocessController,
        config_store: ConfigStore,
        shutdown_trigger: Callable[[int], None],
    ) -> "KresManager":
        """
        Creates new instance of KresManager.
        """

        inst = KresManager(shutdown_trigger, _i_know_what_i_am_doing=True)
        await inst._async_init(subprocess_controller, config_store)  # pylint: disable=protected-access
        return inst

    async def _async_init(self, subprocess_controller: SubprocessController, config_store: ConfigStore) -> None:
        self._controller = subprocess_controller
        self._config_store = config_store

        # initialize subprocess controller
        logger.debug("Starting controller")
        await self._controller.initialize_controller(config_store.get())
        self._watchdog_task = create_task(self._watchdog())
        logger.debug("Looking for already running workers")
        await self._collect_already_running_workers()

        # register and immediately call a callback that applies policy rules configuration
        await config_store.register_on_change_callback(
            only_on_real_changes(lambda config: [config.views, config.local_data, config.forward])(
                self.apply_policy_rules_config
            )
        )

        # register and immediately call a verififier that validates config with 'canary' kresd process
        await config_store.register_verifier(self.validate_config)

        # register and immediately call a callback to apply config to all 'kresd' workers and 'cache-gc'
        await config_store.register_on_change_callback(
            only_on_real_changes(
                lambda config: [
                    config.nsid,
                    config.hostname,
                    config.workers,
                    config.max_workers,
                    config.webmgmt,
                    config.options,
                    config.network,
                    config.forward,
                    config.cache,
                    config.dnssec,
                    config.dns64,
                    config.logging,
                    config.monitoring,
                    config.lua,
                ]
            )(self.apply_config)
        )

        # register controller config change listeners
        await config_store.register_verifier(_deny_max_worker_changes)

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
            elif subp.type == SubprocessType.POLICY_LOADER:
                assert self._policy_loader is None
                self._policy_loader = subp
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

    async def _run_policy_loader(self, config: KresConfig) -> None:
        if self._policy_loader:
            await self._policy_loader.start(config)
        else:
            subprocess = await self._controller.create_subprocess(config, SubprocessType.POLICY_LOADER)
            await subprocess.start()
            self._policy_loader = subprocess

    def _is_policy_loader_exited(self) -> bool:
        if self._policy_loader:
            return self._policy_loader.status() is SubprocessStatus.EXITED
        return False

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
            except (SubprocessError, SubprocessControllerException):
                logger.error("Kresd with the new config failed to start, rejecting config")
                return Result.err("canary kresd process failed to start. Config might be invalid.")

            logger.debug("Canary process test passed.")
            return Result.ok(None)

    async def _reload_system_state(self) -> None:
        async with self._manager_lock:
            self._workers = []
            self._policy_loader = None
            self._gc = None
            await self._collect_already_running_workers()

    async def apply_config(self, config: KresConfig, _noretry: bool = False) -> None:
        try:
            async with self._manager_lock:
                logger.debug("Applying config to all workers")
                await self._rolling_restart(config)
                await self._ensure_number_of_children(config, int(config.workers))

                if self._is_gc_running() != bool(config.cache.garbage_collector):
                    if config.cache.garbage_collector:
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

    async def apply_policy_rules_config(self, config: KresConfig, _noretry: bool = False) -> None:
        try:
            async with self._manager_lock:
                logger.debug("Running kresd 'policy-loader'")
                await self._run_policy_loader(config)

                # wait for 'policy-loader' to finish
                logger.debug("Waiting for 'policy-loader' to finish loading policy rules")
                while not self._is_policy_loader_exited():
                    await asyncio.sleep(1)

                # command all running 'kresd' workers to reset their old policy rules,
                # unless we're just starting up and there are none to reset
                if get_registered_workers_kresids():
                    logger.debug("Resetting policy rules for all running 'kresd' workers")
                    cmd_results = await command_registered_workers("require('ffi').C.kr_rules_reset()")
                    for worker, res in cmd_results.items():
                        if res != 0:
                            logger.error("Failed to reset policy rules in %s: %s", worker, res)
        except SubprocessControllerException as e:
            if _noretry:
                raise e
            elif self._fix_counter.is_too_high():
                logger.error(f"Failed to apply configured policy rules: {e}")
                logger.error("There have already been problems recently, refusing to try to fix it.")
                await self.forced_shutdown()  # possible improvement - the person who requested this change won't get a response this way
            else:
                logger.error(f"Failed to apply configured policy rules: {e}")
                logger.warning("Reloading system state and trying again.")
                self._fix_counter.increase()
                await self._reload_system_state()
                await self.apply_policy_rules_config(config, _noretry=True)

    async def stop(self):
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()  # cancel it
            try:
                await self._watchdog_task  # and let it really finish
            except asyncio.CancelledError:
                pass

        async with self._manager_lock:
            # we could stop all the children one by one right now
            # we won't do that and we leave that up to the subprocess controller to do that while it is shutting down
            await self._controller.shutdown_controller()
            # now, when everything is stopped, let's clean up all the remains
            await asyncio.gather(*[w.cleanup() for w in self._workers])

    async def forced_shutdown(self) -> None:
        logger.warning("Collecting all remaining workers...")
        await self._reload_system_state()
        logger.warning("Terminating...")
        self._shutdown_trigger(1)

    async def _instability_handler(self) -> None:
        if self._fix_counter.is_too_high():
            logger.error(
                "Already attempted to many times to fix system state. Refusing to try again and shutting down."
            )
            await self.forced_shutdown()
            return

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
                if self._policy_loader:
                    expected_ids.append(self._policy_loader.id)

                invoke_callback = False

                for eid in expected_ids:
                    if eid not in detected_subprocesses:
                        logger.error("Subprocess with id '%s' was not found in the system!", eid)
                        invoke_callback = True
                        continue

                    if detected_subprocesses[eid] is SubprocessStatus.FATAL:
                        logger.error("Subprocess '%s' is in FATAL state!", eid)
                        invoke_callback = True
                        continue

                    if detected_subprocesses[eid] is SubprocessStatus.UNKNOWN:
                        logger.warning("Subprocess '%s' is in UNKNOWN state!", eid)

                non_registered_ids = detected_subprocesses.keys() - set(expected_ids)
                if len(non_registered_ids) != 0:
                    logger.error(
                        "Found additional process in the system, which shouldn't be there - %s",
                        non_registered_ids,
                    )
                    invoke_callback = True

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
