from __future__ import annotations

import argparse
from dataclasses import dataclass

from .constants import CONFIG_FILE, VERSION


@dataclass
class KresArgs:
    loglevel: str
    logtarget: str
    config: list[str]


def parse_args() -> KresArgs:
    parser = argparse.ArgumentParser(
        description="A modern, high-performance, modular DNS resolver with DNSSEC validation and advanced policy.",
    )
    parser.add_argument(
        "-V",
        "--version",
        help="Get version",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "--loglevel",
        default="notice",
        choices=["debug", "info", "notice", "warning", "error", "critical"],
        help="Startup logging level before the configuration is loaded.",
    )
    parser.add_argument(
        "--logtarget",
        default="stderr",
        choices=["stdout", "stderr", "syslog"],
        help="Startup logging target before the configuration is loaded.",
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

    args_ns = parser.parse_args()
    return KresArgs(**vars(args_ns))
