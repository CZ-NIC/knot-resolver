from __future__ import annotations

import argparse
import asyncio
import sys

from knot_resolver.constants import CONFIG_FILE, VERSION

from .logging import setup_logging
from .manager import start_manager


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Knot Resolver - caching DNS resolver")
    parser.add_argument(
        "-V",
        "--version",
        help="Get version",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="One or more configuration files to load."
        f" Overrides default configuration file location at '{CONFIG_FILE}'"
        " Files must not contain the same options."
        " However, they may extend individual subsections."
        " The location of the first configuration file determines"
        "the prefix for every relative path in the configuration.",
        type=str,
        nargs="+",
        required=False,
        default=[str(CONFIG_FILE)],
    )
    return parser


def main() -> None:
    parser = setup_parser()
    args = parser.parse_args()

    setup_logging(args.verbose)
    exit_code = asyncio.run(start_manager(config=args.config))
    sys.exit(exit_code)
