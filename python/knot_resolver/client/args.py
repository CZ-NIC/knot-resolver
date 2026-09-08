from __future__ import annotations

import argparse
import importlib
import pkgutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from knot_resolver.constants import CONFIG_FILE, VERSION

from . import commands

if TYPE_CHECKING:
    from .command import KresClientCommand

KRES_CLIENT_NAME = "kresctl"


@dataclass(frozen=True)
class KresClientArgs:
    socket: str | None
    config: Path
    command: type[KresClientCommand]
    command_args: type[KresClientArgs]


def register_subparsers(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    for module_info in pkgutil.iter_modules(commands.__path__):
        if module_info.name.startswith("_"):
            continue

        module = importlib.import_module(f"{commands.__name__}.{module_info.name}")

        register_subparser = getattr(module, "register_subparser", None)
        if register_subparser is None:
            continue

        register_subparser(subparsers)


def get_client_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        KRES_CLIENT_NAME,
        description=(
            "Knot Resolver command-line utility that serves as a client for "
            "communicating with the Knot Resolver management API. "
            "The utility also provides tools to work with the resolver's "
            "declarative configuration (validate, convert, ...)."
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=VERSION,
        help="get version and exit",
    )
    config_or_socket = parser.add_mutually_exclusive_group()
    config_or_socket.add_argument(
        "-s",
        "--socket",
        help="Path to the resolver's management API socket, unix-domain socket, or network interface."
        "Cannot be used together with '--config'.",
    )
    config_or_socket.add_argument(
        "-c",
        "--config",
        type=Path,
        default=CONFIG_FILE,
        metavar="FILE",
        help="Path to the resolver's YAML or JSON configuration file with the management API configuration."
        "Cannot be used together with '--socket'.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run", required=True)
    register_subparsers(subparsers)

    return parser


def parse_client_args() -> KresClientArgs:
    parser = get_client_parser()
    args_ns = parser.parse_args()
    args_ns.config = args_ns.config.absolute()

    command_args: type[KresClientArgs] = args_ns.command_args
    return command_args(**vars(args_ns))
