# mypy: disable-error-code=import-untyped

from __future__ import annotations

import os
import sys
import traceback
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler

if TYPE_CHECKING:
    from collections.abc import Callable

    from supervisor.supervisord import Supervisor

    SupervisordLogLevel = Literal["CRIT", "ERRO", "WARN", "INFO", "DEBG"]

SupervisordLogTarget = Literal["stdout", "stderr", "syslog"]

SERVICE_NAME = "supervisord"
FORWARD_LOGGING_LEVEL = LevelsByName.CRIT
FORWARD_LOGGING_FORMAT = "[%(pid)d]%(stream)s: %(data)s"


@dataclass(frozen=True)
class LoggingPatchConfig:
    logtarget: SupervisordLogTarget


def _make_p_output_dispatcher_log(
    supervisord_handlers: list[StreamHandler], forward_handlers: list[StreamHandler]
) -> Callable[[POutputDispatcher, bytes], None]:
    def _p_output_dispatcher_log(self: POutputDispatcher, data: bytes) -> None:
        """Forward subprocess output to the selected logging backend."""
        if not data:
            return

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = f"Undecodable log data: {data!r}"

        config = self.process.config
        # set logger handlers for forwarding
        config.options.logger.handlers = forward_handlers

        service = config.name
        pid = self.process.pid

        stream = ""
        if self.channel == "stderr":
            stream = " (stderr)"

        # log every line with correct format
        for line in text.splitlines():
            config.options.logger.log(
                FORWARD_LOGGING_LEVEL,
                "%(service)s[%(pid)d]%(stream)s: %(line)s",
                service=service,
                pid=pid,
                stream=stream,
                line=line,
            )
        # revert to the original logger handlers
        config.options.logger.handlers = supervisord_handlers

    return _p_output_dispatcher_log


def _create_logger_handler(fmt: str, level: SupervisordLogLevel, config: LoggingPatchConfig) -> StreamHandler:
    logtarget = config.logtarget

    if logtarget == "syslog":
        return SyslogHandler()
    handler = StreamHandler(sys.stderr) if logtarget == "stderr" else StreamHandler(sys.stdout)

    handler.setFormat(fmt)
    handler.setLevel(level)
    return handler


def inject(supervisord: Supervisor, **config_dict: object) -> None:
    logtarget = config_dict.get("logtarget")

    if logtarget not in ("stdout", "stderr", "syslog"):
        msg = f"Unknown 'logtarget' configuration: {logtarget!r}"
        raise ValueError(msg)

    config = LoggingPatchConfig(
        logtarget=cast("SupervisordLogTarget", logtarget),
    )
    pid = os.getpid()

    try:
        supervisord_handlers: list[StreamHandler] = []
        supervisord_handlers.append(
            _create_logger_handler(
                f"%(asctime)s {SERVICE_NAME}[{pid}]: [%(levelname)s] %(message)s\n",
                supervisord.options.loglevel,
                config,
            ),
        )
        forward_handlers: list[StreamHandler] = []
        forward_handlers.append(
            _create_logger_handler("%(asctime)s %(message)s\n", supervisord.options.loglevel, config)
        )

        supervisord.options.logger.handlers = supervisord_handlers

        # replace output handler for subprocesses
        POutputDispatcher._log = _make_p_output_dispatcher_log(supervisord_handlers, forward_handlers)

    # if we fail to load the module, print some explanation
    # should not happen when run by endusers
    except BaseException:
        traceback.print_exc()
        raise
