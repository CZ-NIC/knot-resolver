# type: ignore
# pylint: disable=protected-access

import sys
import traceback
from typing import Any

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler
from supervisor.supervisord import Supervisor
from typing_extensions import Literal

FORWARD_LOG_LEVEL = LevelsByName.CRIT  # to make sure it's always printed


def empty_function(*args, **kwargs):
    pass


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
            msg = "[%(name)s:%(channel)s] %(data)s"
            config.options.logger.log(FORWARD_LOG_LEVEL, msg, name=config.name, channel=self.channel[3:], data=line)
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
                "[%(asctime)s][supervisor] [%(levelname)s] %(message)s\n",
                supervisord.options.loglevel,
                config["target"],
            )
        )
        forward_handlers.append(
            _create_handler("[%(asctime)s]%(message)s\n", supervisord.options.loglevel, config["target"])
        )
        supervisord.options.logger.handlers = supervisord_handlers

        # replace output handler for subprocesses
        if config["target"] == "syslog":
            POutputDispatcher._log = empty_function
        else:
            POutputDispatcher._log = POutputDispatcher_log

        # this method is called by supervisord when loading the plugin,
        # it should return XML-RPC object, which we don't care about
        # That's why why are returning just None
        return None

    # if we fail to load the module, print some explanation
    # should not happen when run by endusers
    except BaseException:
        traceback.print_exc()
        raise
