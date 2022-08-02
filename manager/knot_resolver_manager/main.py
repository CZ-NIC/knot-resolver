"""
Effectively the same as normal __main__.py. However, we moved it's content over to this
file to allow us to exclude the __main__.py file from black's autoformatting
"""

import argparse
import sys
from pathlib import Path

from knot_resolver_manager import compat
from knot_resolver_manager.constants import DEFAULT_MANAGER_CONFIG_FILE
from knot_resolver_manager.log import logger_startup
from knot_resolver_manager.server import start_server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Knot Resolver - caching DNS resolver")
    parser.add_argument(
        "-c",
        "--config",
        help="Config file to load. Overrides default config location at '" + str(DEFAULT_MANAGER_CONFIG_FILE) + "'",
        type=str,
        nargs=1,
        required=False,
        default=None,
    )
    return parser.parse_args()


def main() -> None:
    # initial logging is to memory until we read the config
    logger_startup()

    # parse arguments
    args = parse_args()

    # where to look for config
    config_path = DEFAULT_MANAGER_CONFIG_FILE if args.config is None else Path(args.config[0])

    exit_code = compat.asyncio.run(start_server(config=config_path))
    sys.exit(exit_code)
