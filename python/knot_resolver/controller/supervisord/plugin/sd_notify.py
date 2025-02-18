# type: ignore
# ruff: noqa: SLF001
# pylint: disable=c-extension-no-member

import os
import signal
import time
from functools import partial
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar

from supervisor.events import ProcessStateEvent, ProcessStateStartingEvent, subscribe
from supervisor.medusa.asyncore_25 import compact_traceback
from supervisor.process import Subprocess
from supervisor.states import ProcessStates
from supervisor.supervisord import Supervisor

from knot_resolver.controller.supervisord.plugin import notify

starting_processes: List[Subprocess] = []


def is_type_notify(proc: Subprocess) -> bool:
    return proc.config.environment is not None and proc.config.environment.get("X-SUPERVISORD-TYPE", None) == "notify"


class NotifySocketDispatcher:
    """
    See supervisor.dispatcher
    """

    def __init__(self, supervisor: Supervisor, fd: int):
        self._supervisor = supervisor
        self.fd = fd
        self.closed = False  # True if close() has been called

    def __repr__(self):
        return f"<{self.__class__.__name__} with fd={self.fd}>"

    def readable(self):
        return True

    def writable(self):
        return False

    def handle_read_event(self):
        logger: Any = self._supervisor.options.logger

        res: Optional[Tuple[int, bytes]] = notify.read_message(self.fd)
        if res is None:
            return  # there was some junk
        pid, data = res

        # pylint: disable=undefined-loop-variable
        for proc in starting_processes:
            if proc.pid == pid:
                break
        else:
            logger.warn(f"ignoring ready notification from unregistered PID={pid}")
            return

        if data.startswith(b"READY=1"):
            # handle case, when some process is really ready

            if is_type_notify(proc):
                proc._assertInState(ProcessStates.STARTING)
                proc.change_state(ProcessStates.RUNNING)
                logger.info(
                    f"success: {proc.config.name} entered RUNNING state, process sent notification via $NOTIFY_SOCKET"
                )
            else:
                logger.warn(f"ignoring READY notification from {proc.config.name}, which is not configured to send it")

        elif data.startswith(b"STOPPING=1"):
            # just accept the message, filter unwanted notifications and do nothing else

            if is_type_notify(proc):
                logger.info(
                    f"success: {proc.config.name} entered STOPPING state, process sent notification via $NOTIFY_SOCKET"
                )
            else:
                logger.warn(
                    f"ignoring STOPPING notification from {proc.config.name}, which is not configured to send it"
                )

        else:
            # handle case, when we got something unexpected
            logger.warn(f"ignoring unrecognized data on $NOTIFY_SOCKET sent from PID={pid}, data='{data!r}'")
            return

    def handle_write_event(self):
        raise ValueError("this dispatcher is not writable")

    def handle_error(self):
        _nil, t, v, tbinfo = compact_traceback()

        self._supervisor.options.logger.error(
            f"uncaptured python exception, closing notify socket {repr(self)} ({t}:{v} {tbinfo})"
        )
        self.close()

    def close(self):
        if not self.closed:
            os.close(self.fd)
            self.closed = True

    def flush(self):
        pass


def keep_track_of_starting_processes(event: ProcessStateEvent) -> None:
    global starting_processes

    proc: Subprocess = event.process

    if isinstance(event, ProcessStateStartingEvent):
        # process is starting
        # if proc not in starting_processes:
        starting_processes.append(proc)

    else:
        # not starting
        starting_processes = [p for p in starting_processes if p.pid is not proc.pid]


notify_dispatcher: Optional[NotifySocketDispatcher] = None


def process_transition(slf: Subprocess) -> None:
    if not is_type_notify(slf):
        return slf

    # modified version of upstream process transition code
    if slf.state == ProcessStates.STARTING:
        if time.time() - slf.laststart > slf.config.startsecs:
            # STARTING -> STOPPING if the process has not sent ready notification
            # within proc.config.startsecs
            slf.config.options.logger.warn(
                f"process '{slf.config.name}' did not send ready notification within {slf.config.startsecs} secs, killing"
            )
            slf.kill(signal.SIGKILL)
            slf.x_notifykilled = True  # used in finish() function to set to FATAL state
            slf.laststart = time.time() + 1  # prevent immediate state transition to RUNNING from happening

    # return self for chaining
    return slf


def subprocess_finish_tail(slf, pid, sts) -> Tuple[Any, Any, Any]:
    if getattr(slf, "x_notifykilled", False):
        # we want FATAL, not STOPPED state after timeout waiting for startup notification
        # why? because it's likely not gonna help to try starting the process up again if
        # it failed so early
        slf.change_state(ProcessStates.FATAL)

        # clear the marker value
        del slf.x_notifykilled

    # return for chaining
    return slf, pid, sts


def supervisord_get_process_map(supervisord: Any, mp: Dict[Any, Any]) -> Dict[Any, Any]:
    global notify_dispatcher
    if notify_dispatcher is None:
        notify_dispatcher = NotifySocketDispatcher(supervisord, notify.init_socket())
        supervisord.options.logger.info("notify: injected $NOTIFY_SOCKET into event loop")

    # add our dispatcher to the result
    assert notify_dispatcher.fd not in mp
    mp[notify_dispatcher.fd] = notify_dispatcher

    return mp


def process_spawn_as_child_add_env(slf: Subprocess, *args: Any) -> Tuple[Any, ...]:
    if is_type_notify(slf):
        slf.config.environment["NOTIFY_SOCKET"] = os.getcwd() + "/supervisor-notify-socket"
    return (slf, *args)


T = TypeVar("T")
U = TypeVar("U")


def chain(first: Callable[..., U], second: Callable[[U], T]) -> Callable[..., T]:
    def wrapper(*args: Any, **kwargs: Any) -> T:
        res = first(*args, **kwargs)
        if isinstance(res, tuple):
            return second(*res)
        return second(res)

    return wrapper


def append(first: Callable[..., T], second: Callable[..., None]) -> Callable[..., T]:
    def wrapper(*args: Any, **kwargs: Any) -> T:
        res = first(*args, **kwargs)
        second(*args, **kwargs)
        return res

    return wrapper


def monkeypatch(supervisord: Supervisor) -> None:
    """Inject ourselves into supervisord code"""

    # append notify socket handler to event loop
    supervisord.get_process_map = chain(supervisord.get_process_map, partial(supervisord_get_process_map, supervisord))

    # prepend timeout handler to transition method
    Subprocess.transition = chain(process_transition, Subprocess.transition)
    Subprocess.finish = append(Subprocess.finish, subprocess_finish_tail)

    # add environment variable $NOTIFY_SOCKET to starting processes
    Subprocess._spawn_as_child = chain(process_spawn_as_child_add_env, Subprocess._spawn_as_child)

    # keep references to starting subprocesses
    subscribe(ProcessStateEvent, keep_track_of_starting_processes)


def inject(supervisord: Supervisor, **_config: Any) -> Any:  # pylint: disable=useless-return
    monkeypatch(supervisord)

    # this method is called by supervisord when loading the plugin,
    # it should return XML-RPC object, which we don't care about
    # That's why why are returning just None
    return None
