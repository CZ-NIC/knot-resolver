# mypy: disable-error-code=import-untyped

from __future__ import annotations

import os
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, assert_never

from supervisor.dispatchers import POutputDispatcher
from supervisor.loggers import LevelsByName, StreamHandler, SyslogHandler

from knot_resolver.logging import SERVICE_NAME_LEN

if TYPE_CHECKING:
    from supervisor.supervisord import Supervisor

    SupervisordLogLevel = Literal["CRIT", "ERRO", "WARN", "INFO", "DEBG"]


SERVICE_NAME = "supervisord"
FORWARD_LOGGING_LEVEL = LevelsByName.CRIT
FORWARD_LOGGING_FORMAT = "[%(pid)d]%(stream)s: %(data)s"


@dataclass
class LoggerPatchConfig:
    logtarget: Literal["stdout", "stderr", "syslog"]


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

        # rjust servise name
        service = config.name.rjust(SERVICE_NAME_LEN)
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


def _create_logger_handler(fmt: str, level: SupervisordLogLevel, config: LoggerPatchConfig) -> StreamHandler:
    logtarget = config.logtarget
    match logtarget:
        case "syslog":
            return SyslogHandler()
        case "stdout":
            handler = StreamHandler(sys.stdout)
        case "stderr":
            handler = StreamHandler(sys.stderr)
        case _:
            assert_never(logtarget)

    handler.setFormat(fmt)
    handler.setLevel(level)
    return handler


def inject(supervisord: Supervisor, **config_dict: object) -> None:
    config: LoggerPatchConfig = LoggerPatchConfig(**config_dict)  # type: ignore[arg-type]

    service = SERVICE_NAME.rjust(SERVICE_NAME_LEN)
    pid = os.getpid()

    try:
        supervisord_handlers: list[StreamHandler] = []
        supervisord_handlers.append(
            _create_logger_handler(
                f"%(asctime)s {service}[{pid}]: [%(levelname)s] %(message)s\n",
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
