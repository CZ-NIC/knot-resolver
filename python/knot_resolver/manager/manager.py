from __future__ import annotations

import asyncio
import errno
import os
import signal
import sys
from pathlib import Path
from time import time
from typing import TYPE_CHECKING

from knot_resolver.config import KresConfig
from knot_resolver.constants import RUN_DIR
from knot_resolver.controller import SupervisordController
from knot_resolver.controller.notify.notify_socket import send_notify_message
from knot_resolver.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from knot_resolver.args import KresArgs
    from knot_resolver.controller.subprocess import Subprocess

logger = get_logger(__name__)


def add_async_signal_handler(sig: signal.Signals, callback: Callable[[], Coroutine[object, object, None]]) -> None:
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(sig, lambda: loop.create_task(callback(), name=f"signal:{sig.name}"))


def remove_async_signal_handler(signal: signal.Signals) -> None:
    loop = asyncio.get_running_loop()
    loop.remove_signal_handler(signal)


async def _sigint_handler_during_shutdown() -> None:
    logger.warning(
        "Ignoring SIGINT received during shutdown. If you want to force a stop the manager right now, use SIGTERM."
    )


async def _sigterm_handler_during_shutdown() -> None:
    logger.warning("Received SIGTERM during shutdown. Invoking the manager's dirty shutdown!")
    sys.exit(128 + signal.SIGTERM)


class KresManager:
    def __init__(self, args: KresArgs, config: KresConfig) -> None:

        self._args = args

        self._controller = SupervisordController(args, config)
        self._exit_code: int = 0

        self._workers: list[Subprocess] | None = None
        self._loader: Subprocess | None = None
        self._cache_gc: Subprocess | None = None

        self._manager_lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def trigger_shutdown(self, exit_code: int) -> None:
        self._shutdown_event.set()
        self._exit_code = exit_code

    async def sigint_handler(self) -> None:
        logger.info("Received SIGINT, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sigterm_handler(self) -> None:
        logger.info("Received SIGTERM, triggering graceful shutdown")
        self.trigger_shutdown(0)

    async def sighup_handler(self) -> None:
        logger.info("Received SIGHUP, reloading configuration file")
        send_notify_message(RELOADING="1")
        # TODO(amrazek): reload configuration
        send_notify_message(READY="1")

    @staticmethod
    def handled_signals() -> set[signal.Signals]:
        return {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}

    def add_signal_handlers(self) -> None:
        add_async_signal_handler(signal.SIGTERM, self.sigterm_handler)
        add_async_signal_handler(signal.SIGINT, self.sigint_handler)
        add_async_signal_handler(signal.SIGHUP, self.sighup_handler)

    def remove_signal_handlers(self) -> None:
        remove_async_signal_handler(signal.SIGTERM)
        remove_async_signal_handler(signal.SIGINT)
        remove_async_signal_handler(signal.SIGHUP)

    async def wait_for_shutdown_event(self) -> None:
        await self._shutdown_event.wait()

    @property
    def exit_code(self) -> int:
        return self._exit_code


async def start_manager(args: KresArgs) -> int:
    logger.notice("Starting Knot Resolver Manager...")
    start_time = time()

    handled_signals = KresManager.handled_signals()
    signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)

    # Ensure that configuration files paths do not change
    # even when the working directory is changed.
    _config_paths = [Path(file).absolute() for file in args.config]

    # TODO(amrazek): load/parse/validate configuration here
    config = KresConfig()

    # TODO(amrazek): set logging level, target, ...

    # TODO(amrazek): use 'rundir' from configuration
    logger.debug("Changing working directory to '%s'", RUN_DIR)
    os.chdir(RUN_DIR)

    manager = KresManager(args, config)

    try:
        await manager.start()
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
            logger.error(f"Failed to start the manager: {e!s}")
            await manager.stop()
            return 1
        raise

    manager.add_signal_handlers()
    signal.pthread_sigmask(signal.SIG_UNBLOCK, handled_signals)

    logger.info("The manager fully initialized in %.3f seconds and running..", time() - start_time)
    send_notify_message(READY="1")

    await manager.wait_for_shutdown_event()

    signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
    manager.remove_signal_handlers()
    add_async_signal_handler(signal.SIGTERM, _sigterm_handler_during_shutdown)
    add_async_signal_handler(signal.SIGINT, _sigint_handler_during_shutdown)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})

    logger.info("Stopping the manager...")
    send_notify_message(STOPPING="1")
    await manager.stop()

    logger.info("The manager has been running for %.3f seconds...", time() - start_time)
    return manager.exit_code
