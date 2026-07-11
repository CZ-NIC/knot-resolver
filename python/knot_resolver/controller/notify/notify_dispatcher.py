# mypy: disable-error-code=import-untyped

from __future__ import annotations

from supervisor.supervisord import Supervisor

from knot_resolver.constants import NOTIFY_SUPPORT

if NOTIFY_SUPPORT:
    import os
    import signal
    import socket
    import time
    from functools import partial, wraps
    from pathlib import Path
    from typing import TYPE_CHECKING

    from supervisor.events import ProcessStateEvent, ProcessStateStartingEvent, subscribe
    from supervisor.medusa.asyncore_25 import compact_traceback
    from supervisor.process import Subprocess
    from supervisor.states import ProcessStates

    from knot_resolver.controller.config import X_TYPE_NOTIFY, X_TYPE_VAR_NAME

    from .notify_socket import NOTIFY_SOCKET_ENV_VAR, NOTIFY_SOCKET_NAME, init_notify_socket, read_notify_socket

    if TYPE_CHECKING:
        from collections.abc import Callable
        from typing import Any, ParamSpec, TypeVar, TypeVarTuple

        P = ParamSpec("P")
        T = TypeVar("T")
        U = TypeVar("U")
        Ts = TypeVarTuple("Ts")

    def chain_call(
        first: Callable[P, U | tuple[Any, ...]],
        second: Callable[..., T],
    ) -> Callable[P, T]:
        @wraps(first)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            result = first(*args, **kwargs)
            if isinstance(result, tuple):
                return second(*result)
            return second(result)

        return wrapper

    def append_call(
        first: Callable[P, T],
        second: Callable[P, object],
    ) -> Callable[P, T]:
        @wraps(first)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            result = first(*args, **kwargs)
            second(*args, **kwargs)
            return result

        return wrapper

    def is_subprocess_x_type_notify(subprocess: Subprocess) -> bool:
        env = subprocess.config.environment
        return bool(env and env.get(X_TYPE_VAR_NAME) == X_TYPE_NOTIFY)

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
            if self.notify_dispatcher is None:
                self.notify_dispatcher = NotifyDispatcher(supervisord, self)
                supervisord.options.logger.info("injected 'notify' feature into event loop")

            mp[self.notify_dispatcher.fd] = self.notify_dispatcher
            return mp

    class NotifyDispatcher:
        def __init__(self, supervisor: Supervisor, plugin: NotifyPlugin):
            self._supervisor = supervisor
            self._plugin = plugin

            sock = init_notify_socket()
            self.fd = sock.detach()
            self.closed: bool = False

        def readable(self) -> bool:
            return True

        def writable(self) -> bool:
            return False

        def handle_read_event(self) -> None:
            logger = self._supervisor.options.logger

            sock = socket.socket(fileno=self.fd)
            try:
                result: tuple[int, bytes] | None = read_notify_socket(sock)
            finally:
                sock.detach()

            if result is None:
                return

            pid, data = result

            # find subprocess by PID
            subprocess: Subprocess | None = None
            for starting_subprocess in self._plugin.starting_subprocesses.values():
                if starting_subprocess.pid == pid:
                    subprocess = starting_subprocess

            if not subprocess:
                logger.warn(f"ignoring notify message from unregistered subprocess PID={pid}")
                return

            if not is_subprocess_x_type_notify(subprocess):
                logger.warn(
                    f"ignoring notify message {data!r} from {subprocess.config.name}, that is not configured to send it"
                )
                return

            if data.startswith(b"READY=1"):
                subprocess._assertInState(ProcessStates.STARTING)
                subprocess.change_state(ProcessStates.RUNNING)
                logger.info(f"{subprocess.config.name} entered RUNNING state, received READY notify message")
            elif data.startswith(b"STOPPING=1"):
                logger.info(f"{subprocess.config.name} entered STOPPING state, received STOPPING notify message")
            else:
                logger.warn(
                    "ignoring unrecognized data on $NOTIFY_SOCKET sent from"
                    f" '{subprocess.config.name}', PID={pid}, data={data!r}"
                )

        def handle_write_event(self) -> None:
            raise RuntimeError("Write events are not supported by NotifyDispatcher.")

        def handle_error(self) -> None:
            logger = self._supervisor.options.logger

            _, ex_class, ex_instance, tb_info = compact_traceback()
            logger.error(
                f"uncaptured exception, closing notify socket {self!r} ({ex_class.__name__}: {ex_instance})\n{tb_info})"
            )
            self.close()

        def close(self) -> None:
            if not self.closed:
                os.close(self.fd)
                self.closed = True

        def flush(self) -> None:
            return

    def _subprocess_transition(subprocess: Subprocess) -> Subprocess:
        logger = subprocess.config.options.logger

        if not is_subprocess_x_type_notify(subprocess):
            return subprocess

        if (
            subprocess.state == ProcessStates.STARTING
            and time.time() - subprocess.laststart > subprocess.config.startsecs
        ):
            # STARTING -> STOPPING if the process has not sent ready notification
            # within proc.config.startsecs
            logger.warn(
                f"process '{subprocess.config.name}' did not send ready notification"
                f" within {subprocess.config.startsecs} secs, killing"
            )
            subprocess.kill(signal.SIGKILL)
            subprocess.x_notifykilled = True  # used in finish() function to set to FATAL state
            subprocess.laststart = time.time() + 1  # prevent immediate state transition to RUNNING from happening

        return subprocess

    def _subprocess_finish_tail(subprocess: Subprocess, pid: int, sts: object) -> tuple[Subprocess, int, object]:
        if getattr(subprocess, "x_notifykilled", False):
            # we want FATAL, not STOPPED state after timeout waiting for startup notification
            # why? because it's likely not gonna help to try starting the process up again if
            # it failed so early
            subprocess.change_state(ProcessStates.FATAL)

            # clear the marker value
            del subprocess.x_notifykilled
        return subprocess, pid, sts

    def _subprocess_spawn_as_child_add_notify_socket_env_var(
        subprocess: Subprocess, *args: *Ts
    ) -> tuple[Subprocess, *Ts]:
        if is_subprocess_x_type_notify(subprocess):
            subprocess.config.environment[NOTIFY_SOCKET_ENV_VAR] = str(Path.cwd() / NOTIFY_SOCKET_NAME)
        return (subprocess, *args)

    def notify_monkey_patch(supervisord: Supervisor) -> None:
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
    logger = supervisord.options.logger

    if NOTIFY_SUPPORT:
        logger.info("The 'notify' feature is supported on this system. Patching supervisord to support it ...")
        notify_monkey_patch(supervisord)
    else:
        logger.info("The 'notify' feature is not supported on this system. It is available only on Linux systems.")
