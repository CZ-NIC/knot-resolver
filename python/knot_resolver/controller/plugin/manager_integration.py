# ruff: noqa: G010
# mypy: disable-error-code=import-untyped

from __future__ import annotations

import atexit
import os
import signal
from typing import TYPE_CHECKING, Any

from supervisor.compat import as_string
from supervisor.events import (
    ProcessStateFatalEvent,
    ProcessStateRunningEvent,
    ProcessStateStartingEvent,
    ProcessStateStoppingEvent,
    subscribe,
)
from supervisor.options import ServerOptions
from supervisor.states import SupervisorStates

from knot_resolver.controller.notify.notify_socket import NOTIFY_SOCKET, send_notify_socket_message

if TYPE_CHECKING:
    from supervisor.loggers import Logger
    from supervisor.process import Subprocess
    from supervisor.supervisord import Supervisor

MANAGER_NAME = "manager"


def _exit_failure() -> None:
    os._exit(1)


def inject(supervisord: Supervisor, **_config: Any) -> None:
    logger: Logger = supervisord.options.logger

    # Preserve the systemd NOTIFY_SOCKET before Supervisord modifies the environment.
    systemd_notify_socket = os.environ.get(NOTIFY_SOCKET)

    def notify(**status: str) -> None:
        if systemd_notify_socket is not None:
            send_notify_socket_message(systemd_notify_socket, **status)

    def is_manager(event: Any) -> bool:
        process: Subprocess = event.process
        return as_string(process.config.name) == MANAGER_NAME

    # Notify systemd that initialization has started.
    notify(STATUS="Initializing supervisord...")


    def on_starting(event: ProcessStateStartingEvent) -> None:
        if is_manager(event):
            notify(STATUS="Starting services...")
    subscribe(ProcessStateStartingEvent, on_starting)

    def on_running(event: ProcessStateRunningEvent) -> None:
        if is_manager(event):
            notify(READY="1", STATUS="Ready")
    subscribe(ProcessStateRunningEvent, on_running)

    def on_stopping(event: ProcessStateStoppingEvent) -> None:
        if is_manager(event):
            notify(STOPPING="1", STATUS="Stopping services...",)
    subscribe(ProcessStateStoppingEvent, on_stopping)

    def on_fatal(event: ProcessStateFatalEvent) -> None:
        if not is_manager(event):
            return

        logger.critical("The manager process entered FATAL state! Shutting down...")
        supervisord.options.mood = SupervisorStates.SHUTDOWN

        # Ensure supervisord exits with status 1 after shutdown.
        atexit.register(_exit_failure)
    subscribe(ProcessStateFatalEvent, on_fatal)

    def get_signal(self: ServerOptions) -> int | None:
        sig = self.signal_receiver.get_signal()

        if sig != signal.SIGHUP:
            return sig

        logger.info("received SIGHUP, forwarding to the process 'manager'")
        try:
            manager = supervisord.process_groups[MANAGER_NAME].processes[
                MANAGER_NAME
            ]
        except KeyError:
            logger.warn("the manager process is not available; cannot forward SIGHUP")
            return None

        os.kill(manager.pid, signal.SIGHUP)
        return None

    # Forward SIGHUP to the manager process
    ServerOptions.get_signal = get_signal
