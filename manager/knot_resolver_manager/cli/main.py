import argparse
import importlib
import os

from knot_resolver_manager.cli.command import install_commands_parsers
from knot_resolver_manager.cli.kresctl import Kresctl


def autoimport_commands() -> None:
    prefix = "knot_resolver_manager.cli.cmd."
    for module_name in os.listdir(os.path.dirname(__file__) + "/cmd"):
        if module_name[-3:] != ".py":
            continue
        importlib.import_module(f"{prefix}{module_name[:-3]}")


def create_main_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "kresctl",
        description="Command-line utility that helps communicate with Knot Resolver's management API."
        "It also provides tooling to work with declarative configuration (validate, convert).",
    )
    # parser.add_argument(
    #     "-i",
    #     "--interactive",
    #     action="store_true",
    #     help="Interactive mode of kresctl utility",
    #     default=False,
    #     required=False,
    # )
    config_or_socket = parser.add_mutually_exclusive_group()
    config_or_socket.add_argument(
        "-s",
        "--socket",
        action="store",
        type=str,
        help="Optional, path to Unix-domain socket or network interface of the management API. "
        "Cannot be used together with '--config'.",
        default=[],
        nargs=1,
        required=False,
    )
    config_or_socket.add_argument(
        "-c",
        "--config",
        action="store",
        type=str,
        help="Optional, path to Knot Resolver declarative configuration to retrieve socket or network "
        "interface of the management API from. Cannot be used together with '--socket'.",
        default=[],
        nargs=1,
        required=False,
    )
    return parser


def main() -> None:
    autoimport_commands()
    parser = create_main_argument_parser()
    install_commands_parsers(parser)

    namespace = parser.parse_args()
    kresctl = Kresctl(namespace, parser)
    kresctl.execute()

    # if namespace.interactive or len(vars(namespace)) == 2:
    #     kresctl.interactive()
    # else:
    #     kresctl.execute()
