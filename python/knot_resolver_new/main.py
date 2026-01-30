from __future__ import annotations

import argparse
import asyncio
import sys

from .constants import CONFIG_FILE, VERSION
from .logging import setup_logging
from .resolver import start_resolver


def setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Knot Resolver",
    )
    parser.add_argument(
        "-V",
        "--version",
        help="Get version",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose logging",
        action="store_true",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Optional, path to one or more configuration files (YAML/JSON).",
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
    exit_code = asyncio.run(start_resolver(config=args.config))
    sys.exit(exit_code)
