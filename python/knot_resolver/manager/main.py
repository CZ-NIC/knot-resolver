"""
Effectively the same as normal __main__.py. However, we moved it's content over to this
file to allow us to exclude the __main__.py file from black's autoformatting
"""

import argparse
import sys
from typing import NoReturn

from knot_resolver.constants import CONFIG_FILE, VERSION
from knot_resolver.manager.logger import logger_startup
from knot_resolver.manager.server import start_server
from knot_resolver.utils import compat


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


def main() -> NoReturn:
    # initial logging is to memory until we read the config
    logger_startup()

    # parse arguments
    args = parse_args()

    exit_code = compat.asyncio.run(start_server(config=args.config))
    sys.exit(exit_code)
