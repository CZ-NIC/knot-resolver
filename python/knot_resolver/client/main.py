import argparse
import importlib
import os

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

    namespace, _ = parser.parse_known_args()
    # namespace = parser.parse_args()
    client = KresClient(namespace, parser)
    client.execute()

    # if namespace.interactive or len(vars(namespace)) == 2:
    #     client.interactive()
    # else:
    #     client.execute()
