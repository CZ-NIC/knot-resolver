# type: ignore
# pylint: disable=protected-access
import atexit
import os
from typing import Any, Optional

from supervisor.compat import as_string
from supervisor.events import ProcessStateFatalEvent, ProcessStateRunningEvent, ProcessStateStartingEvent, subscribe
from supervisor.process import Subprocess
from supervisor.states import SupervisorStates
from supervisor.supervisord import Supervisor

from knot_resolver_manager.utils.systemd_notify import systemd_notify

superd: Optional[Supervisor] = None


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
    if processname == "manager":
        # manager has sucessfully started, report it upstream
        systemd_notify(STATUS="Starting services...")


def check_for_runnning_manager(event: ProcessStateRunningEvent) -> None:
    assert superd is not None

    proc: Subprocess = event.process
    processname = as_string(proc.config.name)
    if processname == "manager":
        # manager has sucessfully started, report it upstream
        systemd_notify(READY="1", STATUS="Ready")


def make_rpcinterface(supervisord: Supervisor, **_config: Any) -> Any:  # pylint: disable=useless-return
    global superd
    superd = supervisord

    # This status notification here unsets the env variable $NOTIFY_SOCKET provided by systemd
    # and stores it locally. Therefore, it shouldn't clash with $NOTIFY_SOCKET we are providing
    # downstream
    systemd_notify(STATUS="Initializing supervisord...")

    # register events
    subscribe(ProcessStateFatalEvent, check_for_fatal_manager)
    subscribe(ProcessStateStartingEvent, check_for_starting_manager)
    subscribe(ProcessStateRunningEvent, check_for_runnning_manager)

    # this method is called by supervisord when loading the plugin,
    # it should return XML-RPC object, which we don't care about
    # That's why why are returning just None
    return None
