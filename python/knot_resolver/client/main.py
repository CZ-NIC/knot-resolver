import argparse
import importlib
import os
import sys

from knot_resolver.constants import VERSION

from .client import KRES_CLIENT_NAME, KresClient
from .command import install_commands_parsers


def auto_import_commands() -> None:
    prefix = f"{'.'.join(__name__.split('.')[:-1])}.commands."
    for module_name in os.listdir(os.path.dirname(__file__) + "/commands"):
        if module_name[-3:] != ".py":
            continue
        importlib.import_module(f"{prefix}{module_name[:-3]}")


def create_main_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        KRES_CLIENT_NAME,
        description="Knot Resolver command-line utility that serves as a client for communicating with the Knot Resolver management API."
        " The utility also provides tools to work with the resolver's declarative configuration (validate, convert, ...).",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=VERSION,
        help="Get version",
    )
    # parser.add_argument(
    #     "-i",
    #     "--interactive",
    #     action="store_true",
    #     help="Use the utility in interactive mode.",
    #     default=False,
    #     required=False,
    # )
    config_or_socket = parser.add_mutually_exclusive_group()
    config_or_socket.add_argument(
        "-s",
        "--socket",
        action="store",
        type=str,
        help="Optional, path to the resolver's management API, unix-domain socket, or network interface."
        " Cannot be used together with '--config'.",
        default=[],
        nargs=1,
        required=False,
    )
    config_or_socket.add_argument(
        "-c",
        "--config",
        action="store",
        type=str,
        help="Optional, path to the resolver's declarative configuration to retrieve the management API configuration."
        " Cannot be used together with '--socket'.",
        default=[],
        nargs=1,
        required=False,
    )
    return parser


def main() -> None:
    auto_import_commands()
    parser = create_main_argument_parser()
    install_commands_parsers(parser)

    # TODO: This is broken with unpatched versions of poethepoet, because they drop the `--` pseudo-argument.
    # Patch submitted at <https://github.com/nat-n/poethepoet/pull/163>.
    try:
        pa_index = sys.argv.index("--", 1)
        argv_to_parse = sys.argv[1:pa_index]
        argv_extra = sys.argv[(pa_index + 1) :]
    except ValueError:
        argv_to_parse = sys.argv[1:]
        argv_extra = []

    namespace = parser.parse_args(argv_to_parse)
    if hasattr(namespace, "extra"):
        raise TypeError("'extra' is already an attribute - this is disallowed for commands")
    namespace.extra = argv_extra

    client = KresClient(namespace, parser)
    client.execute()

    # if namespace.interactive or len(vars(namespace)) == 2:
    #     client.interactive()
    # else:
    #     client.execute()
