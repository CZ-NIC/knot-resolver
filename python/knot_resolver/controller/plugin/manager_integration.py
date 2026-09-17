# type: ignore
# pylint: disable=protected-access
import atexit
import os
import signal
from typing import Any, Optional

from supervisor.compat import as_string
from supervisor.events import (
    ProcessStateFatalEvent,
    ProcessStateRunningEvent,
    ProcessStateStartingEvent,
    ProcessStateStoppingEvent,
    subscribe,
)
from supervisor.options import ServerOptions
from supervisor.process import Subprocess
from supervisor.states import SupervisorStates
from supervisor.supervisord import Supervisor

from .notify_socket import send_notify_socket_message, NOTIFY_SOCKET

superd: Optional[Supervisor] = None


SYSTEMD_NOTIFY_SOCKET: Optional[str] = os.environ.get(NOTIFY_SOCKET)


def check_for_fatal_manager(event: ProcessStateFatalEvent) -> None:
    assert superd is not None

    proc: Subprocess = event.process
    processname = as_string(proc.config.name)
    if processname == "manager":
        # stop the whole supervisord gracefully
        superd.options.logger.critical("manager process entered FATAL state! Shutting down")
        superd.options.mood = SupervisorStates.SHUTDOWN

        # force the interpreter to exit with exit code 1
        atexit.register(lambda: os._exit(1))


def check_for_starting_manager(event: ProcessStateStartingEvent) -> None:
    assert superd is not None

    proc: Subprocess = event.process
    processname = as_string(proc.config.name)
    if processname == "manager" and SYSTEMD_NOTIFY_SOCKET is not None:
        # manager has sucessfully started, report it upstream
        send_notify_socket_message(SYSTEMD_NOTIFY_SOCKET, STATUS="Starting services...")


def check_for_runnning_manager(event: ProcessStateRunningEvent) -> None:
    assert superd is not None

    proc: Subprocess = event.process
    processname = as_string(proc.config.name)
    if processname == "manager" and SYSTEMD_NOTIFY_SOCKET is not None:
        # manager has sucessfully started, report it upstream
        send_notify_socket_message(SYSTEMD_NOTIFY_SOCKET, READY="1", STATUS="Ready")


def check_for_stopping_manager(event: ProcessStateStoppingEvent) -> None:
    assert superd is not None

    proc: Subprocess = event.process
    processname = as_string(proc.config.name)
    if processname == "manager" and SYSTEMD_NOTIFY_SOCKET is not None:
        # manager is stopping, report it upstream
        send_notify_socket_message(SYSTEMD_NOTIFY_SOCKET, STOPPING="1", STATUS="Stopping services...")


def get_server_options_signal(self):
    sig = self.signal_receiver.get_signal()
    if sig == signal.SIGHUP and superd is not None:
        superd.options.logger.info("received SIGHUP, forwarding to the process 'manager'")
        manager_pid = superd.process_groups["manager"].processes["manager"].pid
        os.kill(manager_pid, signal.SIGHUP)
        return None

    return sig


def inject(supervisord: Supervisor, **_config: Any) -> Any:  # pylint: disable=useless-return
    global superd
    superd = supervisord

    # This status notification here unsets the env variable $NOTIFY_SOCKET provided by systemd
    # and stores it locally. Therefore, it shouldn't clash with $NOTIFY_SOCKET we are providing
    # downstream
    if SYSTEMD_NOTIFY_SOCKET is not None:
        send_notify_socket_message(SYSTEMD_NOTIFY_SOCKET, STATUS="Initializing supervisord...")

    # register events
    subscribe(ProcessStateFatalEvent, check_for_fatal_manager)
    subscribe(ProcessStateStartingEvent, check_for_starting_manager)
    subscribe(ProcessStateRunningEvent, check_for_runnning_manager)
    subscribe(ProcessStateStoppingEvent, check_for_stopping_manager)

    # forward SIGHUP to manager
    ServerOptions.get_signal = get_server_options_signal

    # this method is called by supervisord when loading the plugin,
    # it should return XML-RPC object, which we don't care about
    # That's why why are returning just None
    return None
