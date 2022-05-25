import os
import signal
from typing import Any, Dict, List, Optional, Tuple

from supervisor.events import ProcessStateEvent, ProcessStateStartingEvent, subscribe
from supervisor.medusa.asyncore_25 import compact_traceback
from supervisor.options import ServerOptions
from supervisor.process import Subprocess
from supervisor.states import ProcessStates
from supervisor.supervisord import Supervisor

from knot_resolver_manager.kresd_controller.supervisord.plugin import notify

starting_processes: List[Subprocess] = []


class NotifySocketDispatcher:
    """
    See supervisor.dispatcher
    """

    def __init__(self, supervisor: Supervisor, fd: int):
        self._supervisor = supervisor
        self.fd = fd
        self.closed = False  # True if close() has been called

    def __repr__(self):
        return "<%s with fd=%s>" % (self.__class__.__name__, self.fd)

    def readable(self):
        return True

    def writable(self):
        return False

    def handle_read_event(self):
        res: Optional[Tuple[int, bytes]] = notify.read_message(self.fd)
        if res is None:
            return None  # there was some junk
        pid, data = res

        if data.startswith(b"READY=1"):
            # some process is really ready
            global starting_processes

            for proc in starting_processes:
                if proc.pid == pid:
                    break
            else:
                print(f"[notify] we've got ready notification from some unknown pid={pid}")
                return None

            print("[notify] received ready notification, marking as RUNNING")
            proc._assertInState(ProcessStates.STARTING)
            proc.change_state(ProcessStates.RUNNING)
        else:
            # we got some junk
            print(f"[notify] we've got some junk on the socket from pid={pid}: '{data!r}'")
            return None

    def handle_write_event(self):
        raise ValueError("this dispatcher is not writable")

    def handle_error(self):
        nil, t, v, tbinfo = compact_traceback()

        print("uncaptured python exception, closing notify socket %s (%s:%s %s)" % (repr(self), t, v, tbinfo))
        self.close()

    def close(self):
        if not self.closed:
            os.close(self.fd)
            self.closed = True

    def flush(self):
        pass


def on_process_state_change(event: ProcessStateEvent) -> None:
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


def monkeypatch(supervisord: Supervisor) -> None:
    """We inject ourselves into supervisord code:

    - inject our notify socket to the event loop
    - subscribe to all state change events
    """

    old: Any = supervisord.get_process_map

    def get_process_map(*args: Any, **kwargs: Any) -> Dict[Any, Any]:
        global notify_dispatcher
        if notify_dispatcher is None:
            notify_dispatcher = NotifySocketDispatcher(supervisord, notify.init_socket())
            supervisord.options.logger.info("notify: injected $NOTIFY_SOCKET into event loop")

        # call the old method
        res = old(*args, **kwargs)

        # add our dispatcher to the result
        assert notify_dispatcher.fd not in res
        res[notify_dispatcher.fd] = notify_dispatcher

        return res

    supervisord.get_process_map = get_process_map

    # subscribe to events
    subscribe(ProcessStateEvent, on_process_state_change)


def make_rpcinterface(supervisord: Supervisor, **config: Any) -> Any:
    monkeypatch(supervisord)
    return None
