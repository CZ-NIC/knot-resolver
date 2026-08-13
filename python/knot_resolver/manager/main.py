"""
Effectively the same as normal __main__.py.

However, we moved it's content over to this
file to allow us to exclude the __main__.py file from black's autoformatting
"""

import argparse
import asyncio
import ctypes
import ctypes.util
import logging
import platform
import sys
from typing import NoReturn

from knot_resolver.constants import CONFIG_FILE, VERSION
from knot_resolver.manager.logger import logger_startup
from knot_resolver.manager.server import start_server

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Knot Resolver - caching DNS resolver")
    parser.add_argument(
        "-V",
        "--version",
        help="Get version",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "-c",
        "--config",
        help="One or more configuration files to load."
        f" Overrides default configuration file location at '{str(CONFIG_FILE)}'"
        " Files must not contain the same options."
        " However, they may extend individual subsections."
        " The location of the first configuration file determines"
        "the prefix for every relative path in the configuration.",
        type=str,
        nargs="+",
        required=False,
        default=[str(CONFIG_FILE)],
    )
    return parser.parse_args()


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


def main() -> NoReturn:
    # initial logging is to memory until we read the config
    logger_startup()

    # Disable Transparent Huge Pages on Linux for this process and all children.
    # THP causes large memory footprint in kresd processes (peaks and not returning memory).
    disable_thp()

    # parse arguments
    args = parse_args()

    exit_code = asyncio.run(start_server(config=args.config))
    sys.exit(exit_code)
