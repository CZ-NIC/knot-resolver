# type: ignore
# pylint: disable=protected-access

import os
import sys
import traceback
from typing import Any, Literal

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler
from supervisor.supervisord import Supervisor

FORWARD_LOG_LEVEL = LevelsByName.CRIT  # to make sure it's always printed


def empty_function(*args, **kwargs):
    pass


FORWARD_MSG_FORMAT: str = "%(name)s[%(pid)d]%(stream)s: %(data)s"


def POutputDispatcher_log(self: POutputDispatcher, data: bytearray):
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
            if self.channel == "stderr":
                stream = " (stderr)"
            config.options.logger.log(
                FORWARD_LOG_LEVEL, FORWARD_MSG_FORMAT, name=config.name, stream=stream, data=line, pid=self.process.pid
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
        POutputDispatcher._log = POutputDispatcher_log

        # we forward stdio in all cases, even when logging to syslog. This should prevent the unforturtunate
        # case of swallowing an error message leaving the users confused. To make the forwarded lines obvious
        # we just prepend a explanatory string at the beginning of all messages
        if config["target"] == "syslog":
            global FORWARD_MSG_FORMAT
            FORWARD_MSG_FORMAT = "captured stdio output from " + FORWARD_MSG_FORMAT

        # this method is called by supervisord when loading the plugin,
        # it should return XML-RPC object, which we don't care about
        # That's why why are returning just None
        return None

    # if we fail to load the module, print some explanation
    # should not happen when run by endusers
    except BaseException:
        traceback.print_exc()
        raise
