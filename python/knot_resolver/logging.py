from __future__ import annotations

import logging
import logging.handlers
import sys
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .args import KresArgs
    from .datamodel import KresConfig


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


def get_logger(name: str | None = None) -> KresLogger:
    logger = logging.getLogger(name) if name else logging.getLogger()
    return cast("KresLogger", logger)


SERVICE_NAME_LEN = 10

BASIC_FORMAT = "%(name)s: %(message)s"
NO_PREFIX_FORMAT = f"[%(levelname)s] {BASIC_FORMAT}"


def get_pretty_format(service: str, stream: str) -> str:
    return f"%(asctime)s {service}[%(process)d]{stream}: {NO_PREFIX_FORMAT}"


def get_formatter(target: LogTarget, service: str | None = None) -> logging.Formatter:
    if target == LogTarget.SYSLOG:
        return logging.Formatter(BASIC_FORMAT)
    if service is None:
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


def start_logging(args: KresArgs, service: str | None = None) -> None:
    root = get_logger()

    level = _config_to_level[args.loglevel]
    root.setLevel(level)

    target = LogTarget(args.logtarget)
    formatter = get_formatter(target, service)
    handler = get_logging_handler(target)
    handler.setFormatter(formatter)

    root.addHandler(handler)


def reconfigure_logging(config: KresConfig, service: str | None = None, debug: bool = False) -> None:
    root = get_logger()

    if debug:
        root.setLevel(logging.DEBUG)
    elif config.logging.level is not None:
        root.setLevel(_config_to_level[str(config.logging.level)])

    if config.logging.target is not None:
        target = LogTarget(str(config.logging.target))
        formatter = get_formatter(target, service)
        new_handler = get_logging_handler(target)
        new_handler.setFormatter(formatter)

        for old_handler in root.handlers:
            old_handler.flush()
            old_handler.close()
            root.removeHandler(old_handler)

        root.addHandler(new_handler)
