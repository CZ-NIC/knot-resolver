# type: ignore
# pylint: disable=protected-access
"""
Plugin which creates a new fd at `NEW_STDOUT_FD` and a thread copying data from there to actual stdout.
Why would we want this? Because when running under systemd, stdout FD is a socket and we can't open it
by calling `open("/proc/self/fd/1")`. We can do this with pipes though. So in order to transparently pass
stdout from manager to stdout of supervisord, we are configuring manager to use /proc/self/fd/42001 as its
logfile. Then we are routing the data to the actual supervisord's stdout.

Performance should not be a problem as this is not a performance critical component.
"""
import os
import sys
from threading import Thread
from typing import Any

from supervisor.supervisord import Supervisor

# when changing this, change it in supervisord.conf.j2 as well
NEW_STDOUT_FD = 42


class SplicingThread(Thread):
    def __init__(self, source_fd: int, target_fd: int) -> None:
        super().__init__(daemon=True, name=f"FD-splice-{source_fd}->{target_fd}")
        self.source_fd = source_fd
        self.dest_fd = target_fd

    def run(self) -> None:
        if sys.version_info.major >= 3 and sys.version_info.minor >= 10:
            while True:
                os.splice(self.source_fd, self.dest_fd, 1024)  # type: ignore[attr-defined]
        else:
            while True:
                buf = os.read(self.source_fd, 1024)
                os.write(self.dest_fd, buf)


def make_rpcinterface(_supervisord: Supervisor, **_config: Any) -> Any:  # pylint: disable=useless-return
    # create pipe
    (r, w) = os.pipe()
    os.dup2(w, NEW_STDOUT_FD)
    os.close(w)

    # start splicing
    t = SplicingThread(r, sys.stdout.fileno())
    t.start()

    # this method is called by supervisord when loading the plugin,
    # it should return XML-RPC object, which we don't care about
    # That's why why are returning just None
    return None
