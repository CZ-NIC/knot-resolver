from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Any

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
    logging.CRITICAL: "CRITICAL",
    logging.ERROR: "ERROR",
    logging.WARNING: "WARNING",
    NOTICE: "NOTICE",
    logging.INFO: "INFO",
    logging.DEBUG: "DEBUG",
}

logging.addLevelName(NOTICE, _level_to_name[NOTICE])


class KresLogger(logging.Logger):
    def notice(self, message: str, *args: Any, **kwargs: Any) -> None:
        if self.isEnabledFor(NOTICE):
            self._log(NOTICE, message, args, **kwargs)


logging.setLoggerClass(KresLogger)

logger = logging.getLogger(__name__)


def get_log_format() -> str:
    return "[%(levelname)s] %(name)s: %(message)s"


def startup_logger(verbose: bool) -> None:
    err_handler = logging.StreamHandler(sys.stderr)
    err_handler.setFormatter(logging.Formatter(get_log_format()))

    logging_level = logging.DEBUG if verbose else NOTICE
    logging.getLogger().setLevel(logging_level)
    # Until we read the configuration, logging is to memory
    logging.getLogger().addHandler(logging.handlers.MemoryHandler(10_000, logging.ERROR, err_handler))
