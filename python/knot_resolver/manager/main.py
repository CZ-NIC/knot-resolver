"""
Effectively the same as normal __main__.py. However, we moved it's content over to this
file to allow us to exclude the __main__.py file from black's autoformatting
"""

import argparse
import os
import sys
from pathlib import Path
from typing import NoReturn

from knot_resolver import compat
from knot_resolver.manager.constants import CONFIG_FILE_ENV_VAR, DEFAULT_MANAGER_CONFIG_FILE
from knot_resolver.manager.log import logger_startup
from knot_resolver.manager.server import start_server


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


def main() -> NoReturn:
    # initial logging is to memory until we read the config
    logger_startup()

    # parse arguments
    args = parse_args()

    # where to look for config
    config_env = os.getenv(CONFIG_FILE_ENV_VAR)
    if args.config is not None:
        config_path = Path(args.config[0])
    elif config_env is not None:
        config_path = Path(config_env)
    else:
        config_path = DEFAULT_MANAGER_CONFIG_FILE

    exit_code = compat.asyncio.run(start_server(config=config_path))
    sys.exit(exit_code)
