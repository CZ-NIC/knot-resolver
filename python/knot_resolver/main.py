from __future__ import annotations

import asyncio
import ctypes
import ctypes.util
import logging
import platform
import sys

from .args import parse_args
from .logging import start_logging
from .resolver import start_resolver

logger = logging.getLogger(__name__)


def disable_thp() -> None:
    try:
        if platform.system() != "Linux":
            return
        prctl = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True).prctl
        PR_SET_THP_DISABLE = 41  # noqa: N806
        PR_THP_DISABLE_EXCEPT_ADVISED = ctypes.c_ulong(2)  # noqa: N806
        ret = prctl(
            PR_SET_THP_DISABLE, ctypes.c_long(1), PR_THP_DISABLE_EXCEPT_ADVISED, ctypes.c_ulong(0), ctypes.c_ulong(0)
        )
        if ret == 0:
            logger.info("THP disabled except advised.")
            return
        ret = prctl(PR_SET_THP_DISABLE, ctypes.c_long(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))
        if ret == 0:
            logger.info("THP disabled.")
            return
    finally:
        pass


def main() -> None:
    args = parse_args()
    start_logging(args)

    # Disable Transparent Huge Pages on Linux for this process and all children.
    # THP causes large memory footprint in kresd processes (peaks and not returning memory).
    disable_thp()

    exit_code = asyncio.run(start_resolver(args))
    sys.exit(exit_code)
