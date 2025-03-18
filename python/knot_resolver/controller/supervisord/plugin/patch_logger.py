# type: ignore
# pylint: disable=protected-access

import os
import sys
import traceback
import re
from typing import Any, Literal

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler
from supervisor.supervisord import Supervisor
from supervisor.process import Subprocess

FORWARD_LOG_LEVEL = LevelsByName.CRIT  # to make sure it's always printed


def empty_function(*args, **kwargs):
    pass


FORWARD_MSG_FORMAT: str = "%(prefix)s%(name)s[%(pid)d]%(stream)s: %(data)s"
FORWARD_MSG_PREFIX: str = ""

loglevel_re = re.compile(r"<(\d)>(.*)")

def p_output_dispatcher_log(self: POutputDispatcher, data: bytearray):
    if data:
        # parse the input
        if not isinstance(data, bytes):
            text = data
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = "Undecodable: %r" % data

        # print line by line prepending correct prefix to match the style
        config = self.process.config
        config.options.logger.handlers = forward_handlers
        for line in text.splitlines():
            stream = ""
            prefix = ""
            loglevel_match = loglevel_re.match(line)
            if loglevel_match:
                # just strip the loglevel as supervisor cannot handle it;
                # used only for target=syslog without systemd
                line = loglevel_match.group(2)
            else:
                # no loglevel found, mark as stdio output to retain previous behaviour
                if self.channel == "stderr":
                    stream = " (stderr)"
                prefix = FORWARD_MSG_PREFIX
            config.options.logger.log(
                FORWARD_LOG_LEVEL, FORWARD_MSG_FORMAT, prefix=prefix, name=config.name, stream=stream, data=line, pid=self.process.pid
            )
        config.options.logger.handlers = supervisord_handlers


def _create_handler(fmt, level, target: Literal["stdout", "stderr", "syslog"]) -> StreamHandler:
    if target == "syslog":
        handler = SyslogHandler()
    else:
        handler = StreamHandler(sys.stdout if target == "stdout" else sys.stderr)
        handler.setFormat(fmt)
        handler.setLevel(level)
    return handler


# keep stderr FD unchanged if stderr_logfile is empty; same behavior as originally otherwise;
# we use "" as other strings involve creation of file of that name (bool("") == False)
def _prepare_child_fds(self):
    options = self.config.options
    options.dup2(self.pipes['child_stdin'], 0)
    options.dup2(self.pipes['child_stdout'], 1)
    if self.config.stderr_logfile != "":
        if self.config.redirect_stderr:
            options.dup2(self.pipes['child_stdout'], 2)
        else:
            options.dup2(self.pipes['child_stderr'], 2)
    for i in range(3, options.minfds):
        options.close_fd(i)


supervisord_handlers = []
forward_handlers = []

def inject(supervisord: Supervisor, **config: Any) -> Any:  # pylint: disable=useless-return
    try:
        # reconfigure log handlers
        supervisord.options.logger.info("reconfiguring log handlers")
        supervisord_handlers.append(
            _create_handler(
                f"%(asctime)s supervisor[{os.getpid()}]: [%(levelname)s] %(message)s\n",
                supervisord.options.loglevel,
                config["target"],
            )
        )
        forward_handlers.append(
            _create_handler("%(asctime)s %(message)s\n", supervisord.options.loglevel, config["target"])
        )
        supervisord.options.logger.handlers = supervisord_handlers

        # replace output handler for subprocesses
        POutputDispatcher._log = p_output_dispatcher_log  # noqa: SLF001

        # replace setting FDs of subprocesses
        Subprocess._prepare_child_fds = _prepare_child_fds

        # we forward stdio in all cases, even when logging to syslog. This should prevent the unforturtunate
        # case of swallowing an error message leaving the users confused. To make the forwarded lines obvious
        # we just prepend a explanatory string at the beginning of all messages
        if config["target"] == "syslog":
            global FORWARD_MSG_PREFIX
            FORWARD_MSG_PREFIX = "captured stdio output from "

        # this method is called by supervisord when loading the plugin,
        # it should return XML-RPC object, which we don't care about
        # That's why why are returning just None
        return None

    # if we fail to load the module, print some explanation
    # should not happen when run by endusers
    except BaseException:
        traceback.print_exc()
        raise
