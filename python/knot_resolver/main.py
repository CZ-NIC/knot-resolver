from __future__ import annotations

import argparse

from .constants import CONFIG_FILE, VERSION
from .logging import startup_logger
from .resolver import start_resolver


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description = "A modern, high-performance, modular DNS resolver with DNSSEC validation and advanced policy.",
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
        help="Enable verbose (debug) logging",
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
    parser = create_parser()
    args = parser.parse_args()

    startup_logger(args.verbose)
    start_resolver(config=args.config)
