from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from .constants import CONFIG_FILE, VERSION

DEFAULT_DESCRIPTION = (
    "Knot Resolver - A modern, high-performance, modular DNS resolver "
    "with DNSSEC validation and advanced policy."
)


# TODO(amrazek): Use also dataclass(slots=True) once
# the project raises its minimum Python version to 3.10+.
@dataclass(frozen=True)
class KresArgs:
    loglevel: str
    logtarget: str
    config: tuple[Path, ...]


def create_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=VERSION,
        help="Show the version and exit.",
    )
    parser.add_argument(
        "--loglevel",
        choices=("debug", "info", "notice", "warning", "error", "critical"),
        default="notice",
        help="Startup logging level before the configuration is loaded.",
    )
    parser.add_argument(
        "--logtarget",
        choices=("stdout", "stderr", "syslog"),
        default="stderr",
        help="Startup logging target before the configuration is loaded.",
    )
    parser.add_argument(
        "-c",
        "--config",
        nargs="+",
        type=Path,
        default=(CONFIG_FILE,),
        metavar="FILE",
        help="Path to one or more YAML or JSON configuration files.",
    )
    return parser


def parse_args(description: str = DEFAULT_DESCRIPTION) -> KresArgs:
    parser = create_parser(description)
    args_ns = parser.parse_args()

    return KresArgs(
        loglevel=args_ns.loglevel,
        logtarget=args_ns.logtarget,
        config=tuple(path.absolute() for path in args_ns.config),
    )
