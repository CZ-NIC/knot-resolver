# ruff: noqa: G004, G010
# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING

from knot_resolver.constants import NOTIFY_SUPPORT

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any, TypeVar

    from supervisor.loggers import Logger as SupervisorLogger
    from supervisor.supervisord import Supervisor

    T = TypeVar("T")
    U = TypeVar("U")


def chain_call(
    first: Callable[..., U | tuple[Any, ...]],
    second: Callable[..., T],
) -> Callable[..., T]:
    @wraps(first)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        result = first(*args, **kwargs)
        if isinstance(result, tuple):
            return second(*result)
        return second(result)

    return wrapper


def append_call(
    first: Callable[..., T],
    second: Callable[..., object],
) -> Callable[..., T]:
    @wraps(first)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        result = first(*args, **kwargs)
        second(*args, **kwargs)
        return result

    return wrapper


if NOTIFY_SUPPORT:
    import os
    import signal
    import time
    from functools import partial, wraps
    from pathlib import Path
    from typing import TYPE_CHECKING

    from supervisor.events import ProcessStateEvent, ProcessStateStartingEvent, subscribe
    from supervisor.medusa.asyncore_25 import compact_traceback
    from supervisor.process import Subprocess
    from supervisor.states import ProcessStates

    from .notify_socket import NOTIFY_SOCKET, NOTIFY_SOCKET_NAME, init_notify_socket, read_notify_socket

    READY_1 = b"READY=1"
    STOPPING_1 = b"STOPPING=1"

    def is_subprocess_x_type_notify(subprocess: Subprocess) -> bool:
        env: dict[str, str] = subprocess.config.environment
        return bool(env and env.get("X-SUPERVISORD-TYPE") == "notify")

    class NotifyPlugin:
        def __init__(self) -> None:
            self.starting_subprocesses: dict[str, Subprocess] = {}
            self.notify_dispatcher: NotifyDispatcher | None = None

        def track_starting_subprocesses(self, event: ProcessStateEvent) -> None:
            subprocess: Subprocess = event.process
            subprocess_name: str = subprocess.config.name

            if isinstance(event, ProcessStateStartingEvent):
                # subprocess is starting
                self.starting_subprocesses[subprocess_name] = subprocess
            else:
                # subprocess is not starting; remove from starting processes
                self.starting_subprocesses.pop(subprocess_name, None)

        def supervisord_get_process_map(self, supervisord: Supervisor, mp: dict[int, object]) -> dict[int, object]:
            logger: SupervisorLogger = supervisord.options.logger
            if self.notify_dispatcher is None:
                self.notify_dispatcher = NotifyDispatcher(supervisord, self)
                logger.info("Injected notify support into event loop")

            mp[self.notify_dispatcher.fd] = self.notify_dispatcher
            return mp

    class NotifyDispatcher:
        def __init__(self, supervisor: Supervisor, plugin: NotifyPlugin):
            self._supervisor = supervisor
            self._plugin = plugin

            self.fd = init_notify_socket()
            self.closed: bool = False

        def readable(self) -> bool:
            return True

        def writable(self) -> bool:
            return False

        def handle_read_event(self) -> None:
            logger: SupervisorLogger = self._supervisor.options.logger

            result: tuple[int, bytes] | None = read_notify_socket(self.fd)
            if result is None:
                return

            pid, data = result

            # find subprocess by PID
            subprocess: Subprocess | None = None
            for starting_subprocess in self._plugin.starting_subprocesses.values():
                if starting_subprocess.pid == pid:
                    subprocess = starting_subprocess

            if not subprocess:
                logger.warn(f"Ignoring notify message from unregistered subprocess PID={pid}")
                return

            if not is_subprocess_x_type_notify(subprocess):
                logger.warn(
                    f"Ignoring notify message {data!r} from {subprocess.config.name}, that is not configured to send it"
                )
                return

            if data.startswith(READY_1):
                subprocess._assertInState(ProcessStates.STARTING)
                subprocess.change_state(ProcessStates.RUNNING)
                logger.info(f"Subprocess {subprocess.config.name} entered RUNNING state, received READY notification")
            elif data.startswith(STOPPING_1):
                logger.info(
                    f"Subprocess {subprocess.config.name} entered STOPPING state, received STOPPING notification"
                )
            else:
                logger.warn(
                    "Ignoring unrecognized data on notify socket sent from"
                    f" {subprocess.config.name}, PID={pid}, data={data!r}"
                )

        def handle_write_event(self) -> None:
            msg = "Write events are not supported by NotifyDispatcher."
            raise RuntimeError(msg)

        def handle_error(self) -> None:
            logger: SupervisorLogger = self._supervisor.options.logger

            _, ex_class, ex_instance, tb_info = compact_traceback()
            logger.error(
                f"Uncaptured error, closing notify socket {self!r} ({ex_class.__name__}: {ex_instance})\n{tb_info})"
            )
            self.close()

        def close(self) -> None:
            if not self.closed:
                os.close(self.fd)
                self.closed = True

        def flush(self) -> None:
            return

    def _subprocess_transition(subprocess: Subprocess) -> Subprocess:
        logger: SupervisorLogger = subprocess.config.options.logger

        if not is_subprocess_x_type_notify(subprocess):
            return subprocess

        if (
            subprocess.state == ProcessStates.STARTING
            and time.time() - subprocess.laststart > subprocess.config.startsecs
        ):
            # If the process has not sent READY notification within 'proc.config.startsecs'
            # STARTING -> STOPPING
            logger.warn(
                f"Subprocess {subprocess.config.name} did not send READY notification within"
                f" {subprocess.config.startsecs} secs; killing subprocess"
            )
            subprocess.kill(signal.SIGKILL)
            subprocess.x_notifykilled = True  # used in finish() function to set to FATAL state
            subprocess.laststart = time.time() + 1  # prevent immediate state transition to RUNNING from happening

        return subprocess

    def _subprocess_finish_tail(subprocess: Subprocess, pid: int, sts: object) -> tuple[Subprocess, int, object]:
        if getattr(subprocess, "x_notifykilled", False):
            # Use FATAL rather than STOPPED after a startup notification timeout.
            # A process that fails to notify during startup is unlikely to succeed if
            # Supervisor immediately tries to start it again.
            subprocess.change_state(ProcessStates.FATAL)

            del subprocess.x_notifykilled
        return subprocess, pid, sts

    def _subprocess_spawn_as_child_add_notify_socket_env_var(
        subprocess: Subprocess, *args: Any
    ) -> tuple[Subprocess, Any]:
        if is_subprocess_x_type_notify(subprocess):
            subprocess.config.environment[NOTIFY_SOCKET] = str(Path.cwd() / NOTIFY_SOCKET_NAME)
        return (subprocess, *args)

    def notify_support_patch(supervisord: Supervisor) -> None:
        notify_plugin = NotifyPlugin()

        # append notify handler to event loop
        supervisord.get_process_map = chain_call(
            supervisord.get_process_map,
            partial(notify_plugin.supervisord_get_process_map, supervisord),
        )

        # chain timeout handler to transition method
        Subprocess.transition = chain_call(_subprocess_transition, Subprocess.transition)
        Subprocess.finish = append_call(Subprocess.finish, _subprocess_finish_tail)

        # add environment variable $NOTIFY_SOCKET to starting processes
        Subprocess._spawn_as_child = chain_call(
            _subprocess_spawn_as_child_add_notify_socket_env_var,
            Subprocess._spawn_as_child,
        )

        # track starting subprocesses
        subscribe(ProcessStateEvent, notify_plugin.track_starting_subprocesses)


def inject(supervisord: Supervisor, **_config: object) -> None:
    logger: SupervisorLogger = supervisord.options.logger

    if NOTIFY_SUPPORT:
        logger.info("The 'notify' feature is supported on this system. Patching supervisord to support it ...")
        notify_support_patch(supervisord)
    else:
        logger.warn("The 'notify' feature is not supported on this system. It is available only on Linux systems.")
