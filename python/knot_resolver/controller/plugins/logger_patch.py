from __future__ import annotations

import os
import sys
import traceback
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler

from knot_resolver.logging import SERVICE_NAME_LEN

if TYPE_CHECKING:
    from supervisor.supervisord import Supervisor

    SupervisordLogLevel = Literal["CRIT", "ERRO", "WARN", "INFO", "DEBG"]

FORWARD_LOGGING_FORMAT = "[%(pid)d]%(stream)s: %(data)s"


forward_handlers: list[Any] = []
supervisord_handlers: list[Any] = []


@dataclass
class LoggerPatchConfig:
    logtarget: Literal["stdout", "stderr", "syslog"]


def p_output_dispatcher_log(self: POutputDispatcher, data: bytes) -> None:
    if not data:
        return

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = f"Undecodable log data: {data!r}"

    config = self.process.config
    config.options.logger.handlers = forward_handlers

    service = config.name.rjust(SERVICE_NAME_LEN)
    pid = self.process.pid

    stream = ""
    if self.channel == "stderr":
        stream = " (stderr)"

    for line in text.splitlines():
        config.options.logger.log(
            LevelsByName.CRIT,
            "%(service)s[%(pid)d]%(stream)s: %(line)s",
            service=service,
            pid=pid,
            stream=stream,
            line=line,
        )

    config.options.logger.handlers = supervisord_handlers


def _create_handler(fmt: str, level: SupervisordLogLevel, config: LoggerPatchConfig) -> StreamHandler:
    if config.logtarget == "syslog":
        handler = SyslogHandler()
    else:
        handler = StreamHandler(sys.stdout if config.logtarget == "stdout" else sys.stderr)
        handler.setFormat(fmt)
        handler.setLevel(level)
    return handler


def inject(supervisord: Supervisor, **config: str) -> None:
    config = LoggerPatchConfig(**config)

    pid = os.getpid()
    service = "supervisord".rjust(SERVICE_NAME_LEN)

    try:
        supervisord_handlers.append(
            _create_handler(
                f"%(asctime)s {service}[{pid}]: [%(levelname)s] %(message)s\n",
                supervisord.options.loglevel,
                config,
            ),
        )

        supervisord.options.logger.handlers = supervisord_handlers

        forward_handlers.append(
            _create_handler("%(asctime)s %(message)s\n", supervisord.options.loglevel, config),
        )

        # replace output handler for subprocesses
        POutputDispatcher._log = p_output_dispatcher_log  # noqa: SLF001

    # if we fail to load the module, print some explanation
    # should not happen when run by endusers
    except BaseException:
        traceback.print_exc()
        raise
