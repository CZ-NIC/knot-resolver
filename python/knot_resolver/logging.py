from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .args import KresArgs


class LogTarget(str, Enum):
    STDOUT = "stdout"
    SYSLOG = "syslog"
    STDERR = "stderr"


NOTICE = (logging.WARNING + logging.INFO) // 2

_config_to_level = {
    "critical": logging.CRITICAL,
    "error": logging.ERROR,
    "warning": logging.WARNING,
    "notice": NOTICE,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

_level_to_name = {
    logging.CRITICAL: "CRIT",
    logging.ERROR: "ERRO",
    logging.WARNING: "WARN",
    NOTICE: "NOTI",
    logging.INFO: "INFO",
    logging.DEBUG: "DEBG",
}


class KresLogger(logging.Logger):
    def notice(self, message: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(NOTICE):
            self._log(NOTICE, message, args, **kwargs)


logging.setLoggerClass(KresLogger)


for level, name in _level_to_name.items():
    logging.addLevelName(level, name)


def get_logger(name: str) -> KresLogger:
    return cast(KresLogger, logging.getLogger(name))


SERVICE_NAME_LEN = 13
NO_PREFIX_FORMAT_ENV_VAR = "KRES_LOGGING_NO_PREFIX_FORMAT"

BASIC_FORMAT = "%(name)s: %(message)s"
NO_PREFIX_FORMAT = f"[%(levelname)s] {BASIC_FORMAT}"


def get_pretty_format(service: str, stream: str) -> str:
    service = service.rjust(SERVICE_NAME_LEN)
    return f"%(asctime)s {service}[%(process)d]{stream}: {BASIC_FORMAT}"


def get_formatter(service: str, target: LogTarget) -> logging.Formatter:
    no_prefix = bool(os.environ.get(NO_PREFIX_FORMAT_ENV_VAR) == "true")

    if target == LogTarget.SYSLOG:
        return logging.Formatter(BASIC_FORMAT)
    if no_prefix:
        return logging.Formatter(NO_PREFIX_FORMAT)

    stream = ""
    if target == LogTarget.STDERR:
        stream = "(stderr)"
    return logging.Formatter(get_pretty_format(service, stream))


def get_logging_handler(target: LogTarget) -> logging.Handler:
    if target == LogTarget.SYSLOG:
        return logging.handlers.SysLogHandler(address="/dev/log")
    if target == LogTarget.STDERR:
        return logging.StreamHandler(sys.stderr)
    return logging.StreamHandler(sys.stdout)


def start_logging(service: str, args: KresArgs) -> None:
    level = _config_to_level[args.loglevel]
    formatter = get_formatter(service, LogTarget(args.logtarget))

    handler = get_logging_handler(LogTarget(args.logtarget))
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(logging.handlers.MemoryHandler(10_000, level, handler))
