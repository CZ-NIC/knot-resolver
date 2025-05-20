import asyncio
import logging
import os
import sys
import time
from secrets import token_hex
from subprocess import SubprocessError
from typing import Any, Callable, List, Optional

from knot_resolver.controller.exceptions import SubprocessControllerError
from knot_resolver.controller.interface import Subprocess, SubprocessController, SubprocessStatus, SubprocessType
from knot_resolver.controller.registered_workers import command_registered_workers, get_registered_workers_kresids
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import (
    ConfigStore,
    only_on_no_changes_update,
    only_on_real_changes_update,
    only_on_real_changes_verifier,
)
from knot_resolver.manager.files import files_reload
from knot_resolver.utils.compat.asyncio import create_task
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling.types import NoneType

from .constants import FIX_COUNTER_ATTEMPTS_MAX, FIX_COUNTER_DECREASE_INTERVAL_SEC, PROCESSES_WATCHDOG_INTERVAL_SEC

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
        return self._counter >= FIX_COUNTER_ATTEMPTS_MAX


async def _subprocess_desc(subprocess: Subprocess) -> object:
    return {
        "type": subprocess.type.name,
        "pid": await subprocess.get_pid(),
        "status": subprocess.status().name,
    }


class KresManager:  # pylint: disable=too-many-instance-attributes
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
            raise AssertionError

        self._workers: List[Subprocess] = []
        self._gc: Optional[Subprocess] = None
        self._policy_loader: Optional[Subprocess] = None
        self._manager_lock = asyncio.Lock()
        self._workers_reset_needed: bool = False
        self._controller: SubprocessController
        self._processes_watchdog_task: Optional["asyncio.Task[None]"] = None
        self._fix_counter: _FixCounter = _FixCounter()
        self._config_store: ConfigStore
        self._shutdown_triggers: List[Callable[[int], None]] = []

    @staticmethod
    async def create(
        subprocess_controller: SubprocessController,
        config_store: ConfigStore,
    ) -> "KresManager":
        """
        Creates new instance of KresManager.
        """

        inst = KresManager(_i_know_what_i_am_doing=True)
        await inst._async_init(subprocess_controller, config_store)  # noqa: SLF001
        return inst

    async def _async_init(self, subprocess_controller: SubprocessController, config_store: ConfigStore) -> None:
        self._controller = subprocess_controller
        self._config_store = config_store

        # initialize subprocess controller
        logger.debug("Starting controller")
        await self._controller.initialize_controller(config_store.get())
        self._processes_watchdog_task = create_task(self._processes_watchdog())
        logger.debug("Looking for already running workers")
        await self._collect_already_running_workers()

        # register and immediately call a verifier that loads policy rules into the rules database
        await config_store.register_verifier(self.load_policy_rules)

        # configuration nodes that are relevant to kresd workers and the cache garbage collector
        def config_nodes(config: KresConfig) -> List[Any]:
            return [
                config.nsid,
                config.hostname,
                config.workers,
                config.options,
                config.network,
                config.forward,
                config.cache,
                config.dnssec,
                config.dns64,
                config.logging,
                config.monitoring,
                config.lua,
                config.rate_limiting,
                config.defer,
            ]

        # register and immediately call a verifier that validates config with 'canary' kresd process
        await config_store.register_verifier(only_on_real_changes_verifier(config_nodes)(self.validate_config))

        # register and immediately call a callback to apply config to all 'kresd' workers and 'cache-gc'
        await config_store.register_on_change_callback(only_on_real_changes_update(config_nodes)(self.apply_config))

        # register callback to reset policy rules for each 'kresd' worker
        await config_store.register_on_change_callback(self.reset_workers_policy_rules)

        # register and immediately call a callback to set new TLS session ticket secret for 'kresd' workers
        await config_store.register_on_change_callback(
            only_on_real_changes_update(config_nodes)(self.set_new_tls_sticket_secret)
        )

        # register callback that reloads files (TLS cert files) if selected configuration has not been changed
        await config_store.register_on_change_callback(only_on_no_changes_update(config_nodes)(files_reload))

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

    def add_shutdown_trigger(self, trigger: Callable[[int], None]) -> None:
        self._shutdown_triggers.append(trigger)

    async def validate_config(self, _old: KresConfig, new: KresConfig) -> Result[NoneType, str]:
        async with self._manager_lock:
            if _old.rate_limiting != new.rate_limiting:
                logger.debug("Unlinking shared ratelimiting memory")
                try:
                    os.unlink(str(_old.rundir) + "/ratelimiting")
                except FileNotFoundError:
                    pass
            if _old.workers != new.workers or _old.defer != new.defer:
                logger.debug("Unlinking shared defer memory")
                try:
                    os.unlink(str(_old.rundir) + "/defer")
                except FileNotFoundError:
                    pass
            logger.debug("Testing the new config with a canary process")
            try:
                # technically, this has side effects of leaving a new process runnning
                # but it's practically not a problem, because
                #   if it keeps running, the config is valid and others will soon join as well
                #   if it crashes and the startup fails, then well, it's not running anymore... :)
                await self._spawn_new_worker(new)
            except (SubprocessError, SubprocessControllerError):
                logger.error("Kresd with the new config failed to start, rejecting config")
                return Result.err("canary kresd process failed to start. Config might be invalid.")

            logger.debug("Canary process test passed.")
            return Result.ok(None)

    async def get_processes(self, proc_type: Optional[SubprocessType]) -> List[object]:
        processes = await self._controller.get_all_running_instances()
        return [await _subprocess_desc(pr) for pr in processes if proc_type is None or pr.type == proc_type]

    async def _reload_system_state(self) -> None:
        async with self._manager_lock:
            self._workers = []
            self._policy_loader = None
            self._gc = None
            await self._collect_already_running_workers()

    async def reset_workers_policy_rules(self, _config: KresConfig) -> None:
        # command all running 'kresd' workers to reset their old policy rules,
        # unless the workers have already been started with a new config so reset is not needed
        if self._workers_reset_needed and get_registered_workers_kresids():
            logger.debug("Resetting policy rules for all running 'kresd' workers")
            cmd_results = await command_registered_workers("require('ffi').C.kr_rules_reset()")
            for worker, res in cmd_results.items():
                if res != 0:
                    logger.error("Failed to reset policy rules in %s: %s", worker, res)
        else:
            logger.debug(
                "Skipped resetting policy rules for all running 'kresd' workers:"
                " the workers are already running with new configuration"
            )

    async def set_new_tls_sticket_secret(self, config: KresConfig) -> None:
        if config.network.tls.sticket_secret or config.network.tls.sticket_secret_file:
            logger.debug("User-configured TLS resumption secret found - skipping auto-generation.")
            return

        logger.debug("Creating TLS session ticket secret")
        secret = token_hex(32)
        logger.debug("Setting TLS session ticket secret for all running 'kresd' workers")
        cmd_results = await command_registered_workers(f"net.tls_sticket_secret('{secret}')")
        for worker, res in cmd_results.items():
            if res not in (0, True):
                logger.error("Failed to set TLS session ticket secret in %s: %s", worker, res)

    async def apply_config(self, config: KresConfig, _noretry: bool = False) -> None:
        try:
            async with self._manager_lock:
                logger.debug("Applying config to all workers")
                await self._rolling_restart(config)
                await self._ensure_number_of_children(config, int(config.workers))

                if self._is_gc_running() != config.cache.garbage_collector.enabled:
                    if config.cache.garbage_collector.enabled:
                        logger.debug("Starting cache GC")
                        await self._start_gc(config)
                    else:
                        logger.debug("Stopping cache GC")
                        await self._stop_gc()
        except SubprocessControllerError as e:
            if _noretry:
                raise
            if self._fix_counter.is_too_high():
                logger.error(f"Failed to apply config: {e}")
                logger.error("There have already been problems recently, refusing to try to fix it.")
                await (
                    self.forced_shutdown()
                )  # possible improvement - the person who requested this change won't get a response this way
            else:
                logger.error(f"Failed to apply config: {e}")
                logger.warning("Reloading system state and trying again.")
                self._fix_counter.increase()
                await self._reload_system_state()
                await self.apply_config(config, _noretry=True)

        self._workers_reset_needed = False

    async def load_policy_rules(self, _old: KresConfig, new: KresConfig) -> Result[NoneType, str]:
        try:
            async with self._manager_lock:
                logger.debug("Running kresd 'policy-loader'")
                await self._run_policy_loader(new)

                # wait for 'policy-loader' to finish
                logger.debug("Waiting for 'policy-loader' to finish loading policy rules")
                while not self._is_policy_loader_exited():
                    await asyncio.sleep(1)

        except (SubprocessError, SubprocessControllerError) as e:
            logger.error(f"Failed to load policy rules: {e}")
            return Result.err("kresd 'policy-loader' process failed to start. Config might be invalid.")

        self._workers_reset_needed = True
        logger.debug("Loading policy rules has been successfully completed")
        return Result.ok(None)

    async def stop(self):
        if self._processes_watchdog_task is not None:
            try:
                self._processes_watchdog_task.cancel()  # cancel it
                await self._processes_watchdog_task  # and let it really finish
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
        for trigger in self._shutdown_triggers:
            trigger(1)

    async def _instability_handler(self) -> None:
        if self._fix_counter.is_too_high():
            logger.error(
                "Already attempted too many times to fix system state. Refusing to try again and shutting down."
            )
            await self.forced_shutdown()
            return

        try:
            logger.warning("Instability detected. Dropping known list of workers and reloading it from the system.")
            self._fix_counter.increase()
            await self._reload_system_state()
            logger.warning("Workers reloaded. Applying old config....")
            await self._config_store.renew()
            logger.warning(f"System stability hopefully renewed. Fix attempt counter is currently {self._fix_counter}")
        except BaseException:
            logger.error("Failed attempting to fix an error. Forcefully shutting down.", exc_info=True)
            await self.forced_shutdown()

    async def _processes_watchdog(self) -> None:  # pylint: disable=too-many-branches  # noqa: PLR0912
        while True:
            await asyncio.sleep(PROCESSES_WATCHDOG_INTERVAL_SEC)

            self._fix_counter.try_decrease()

            try:
                # gather current state
                async with self._manager_lock:
                    detected_subprocesses = await self._controller.get_subprocess_status()
                expected_ids = [x.id for x in self._workers]
                if self._gc:
                    expected_ids.append(self._gc.id)

                invoke_callback = False

                if self._policy_loader:
                    expected_ids.append(self._policy_loader.id)

                for eid in expected_ids:
                    if eid not in detected_subprocesses:
                        logger.error("Subprocess with id '%s' was not found in the system!", eid)
                        invoke_callback = True
                        continue

                    if detected_subprocesses[eid] is SubprocessStatus.FATAL:
                        if self._policy_loader and self._policy_loader.id == eid:
                            logger.info(
                                "Subprocess '%s' is skipped by WatchDog because its status is monitored in a different way.",
                                eid,
                            )
                            continue
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

            except SubprocessControllerError as e:
                # wait few seconds and see if 'processes_watchdog' task is cancelled (during shutdown)
                # otherwise it is an error
                await asyncio.sleep(3)
                invoke_callback = True
                logger.error(f"Processes watchdog failed with SubprocessControllerError: {e}")
            except asyncio.CancelledError:
                raise
            except BaseException:
                invoke_callback = True
                logger.error("Processes watchdog failed with an unexpected exception.", exc_info=True)

            if invoke_callback:
                try:
                    await self._instability_handler()
                except Exception:
                    logger.error("Processes watchdog failed while invoking instability callback", exc_info=True)
                    logger.error("Violently terminating!")
                    sys.exit(1)
