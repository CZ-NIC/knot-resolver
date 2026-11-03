from __future__ import annotations

import logging
import logging.handlers
import sys
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .args import KresArgs
    from .datamodel import KresConfig
    from .datamodel.logging_schema import LogLevelEnum

LOGGING_NOTICE = (logging.WARNING + logging.INFO) // 2

_config_to_level: dict[LogLevelEnum, int] = {
    "crit": logging.CRITICAL,
    "err": logging.ERROR,
    "warning": logging.WARNING,
    "notice": LOGGING_NOTICE,
    "info": logging.INFO,
    "debug": logging.DEBUG,
}

_level_to_name = {
    logging.CRITICAL: "CRIT",
    logging.ERROR: "ERRO",
    logging.WARNING: "WARN",
    LOGGING_NOTICE: "NOTI",
    logging.INFO: "INFO",
    logging.DEBUG: "DEBG",
}


for level, name in _level_to_name.items():
    logging.addLevelName(level, name)


class LogTarget(str, Enum):
    STDOUT = "stdout"
    SYSLOG = "syslog"
    STDERR = "stderr"


class KresLogger(logging.Logger):
    def notice(self, message: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(LOGGING_NOTICE):
            self._log(LOGGING_NOTICE, message, args, **kwargs)


logging.setLoggerClass(KresLogger)


def get_logger(name: str | None = None) -> KresLogger:
    logger = logging.getLogger(name) if name else logging.getLogger()
    return cast("KresLogger", logger)


BASIC_LOGGING_FORMAT = "%(name)s: %(message)s"
NO_PREFIX_LOGGING_FORMAT = f"[%(levelname)s] {BASIC_LOGGING_FORMAT}"


def get_full_logging_format(name: str, stream: str) -> str:
    return f"%(asctime)s {name}[%(process)d]{stream}: {NO_PREFIX_LOGGING_FORMAT}"


def get_logging_formatter(name: str, target: LogTarget, prefix: bool) -> logging.Formatter:
    if target is LogTarget.SYSLOG:
        return logging.Formatter(BASIC_LOGGING_FORMAT)
    if not prefix:
        return logging.Formatter(NO_PREFIX_LOGGING_FORMAT)
    stream = " (stderr)" if target == LogTarget.STDERR else ""
    return logging.Formatter(get_full_logging_format(name, stream))


def get_logging_handler(name: str, target: LogTarget) -> logging.Handler:
    if target == LogTarget.SYSLOG:
        syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
        syslog_handler.ident = f"{name}: "
        return syslog_handler
    if target == LogTarget.STDERR:
        return logging.StreamHandler(sys.stderr)
    return logging.StreamHandler(sys.stdout)


def start_logging(name: str, args: KresArgs, prefix: bool = False) -> None:
    level = _config_to_level[cast("LogLevelEnum", args.loglevel)]
    target = LogTarget(args.logtarget)

    formatter = get_logging_formatter(name, target, prefix)
    handler = get_logging_handler(name, target)
    handler.setFormatter(formatter)

    root = get_logger()
    root.setLevel(level)
    root.addHandler(handler)


def reconfigure_logging(name: str, config: KresConfig, prefix: bool = False) -> None:
    groups = config.logging.groups
    level = logging.DEBUG if groups and name in groups else _config_to_level[config.logging.level]
    target = LogTarget(config.logging.target)

    formatter = get_logging_formatter(name, target, prefix)
    new_handler = get_logging_handler(name, target)
    new_handler.setFormatter(formatter)

    root = get_logger()
    for old_handler in root.handlers:
        old_handler.flush()
        old_handler.close()
        root.removeHandler(old_handler)

    root.setLevel(level)
    root.addHandler(new_handler)
