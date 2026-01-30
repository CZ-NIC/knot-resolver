from __future__ import annotations

import logging
import logging.handlers
import sys
from typing import Any

NOTICE = (logging.WARNING + logging.INFO) // 2
logging.addLevelName(NOTICE, "NOTICE")


def notice(self: logging.Logger, message: str, *args: Any, **kwargs: Any) -> None:
    if self.isEnabledFor(NOTICE):
        self._log(NOTICE, message, args, **kwargs)


logging.Logger.notice = notice


def notice_root(message: str, *args: Any, **kwargs: Any) -> None:
    logging.log(NOTICE, message, *args, **kwargs)


logging.notice = notice_root


def setup_logging(verbose: bool) -> None:
    err_handler = logging.StreamHandler(sys.stderr)
    err_handler.setFormatter(logging.Formatter(logging.BASIC_FORMAT))

    logging_level = logging.DEBUG if verbose else NOTICE
    logging.getLogger().setLevel(logging_level)
    # Until we read the configuration, logging is to memory
    logging.getLogger().addHandler(logging.handlers.MemoryHandler(10_000, logging.ERROR, err_handler))
