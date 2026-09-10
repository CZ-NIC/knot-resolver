from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json, try_to_parse
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
        import argparse


@dataclass(frozen=True)
class ConfigCommandArgs(KresClientArgs):
    operation: ConfigOperation
    path: str
    input: str | None = None
    output_file: Path | None = None
    format: DataFormat = DataFormat.YAML
    value: str | None = None


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    path_help = "Optional, path (JSON pointer, RFC6901) to the configuration resources. "
    " By default, the entire configuration is selected."

    config_parser = subparser.add_parser("config", help="Performs operations on the running resolver's configuration.")
    config_subparsers = config_parser.add_subparsers(dest="operation", help="operation type", required=True)

    # GET operation
    get_op = config_subparsers.add_parser("get", help="Get current configuration from the resolver.")
    get_op.set_defaults(operation=ConfigOperation.GET)
    get_op.add_argument(
        "-p",
        "--path",
        action="store",
        default="",
        help=path_help,
    )
    get_op.add_argument(
        "output_file",
        type=Path,
        nargs="?",
        help="Optional, path to the file where to save exported configuration data."
        " If not specified, data will be printed.",
    )

    get_formats = get_op.add_mutually_exclusive_group()
    get_formats.add_argument(
        "--json",
        const=DataFormat.JSON,
        action="store_const",
        dest="format",
        help="Get configuration data in JSON format.",
    )
    get_formats.add_argument(
        "--yaml",
        const=DataFormat.YAML,
        action="store_const",
        dest="format",
        help="Get configuration data in YAML format, default.",
    )

    # SET operation
    set_op = config_subparsers.add_parser("set", help="Set new configuration for the resolver.")
    set_op.set_defaults(operation=ConfigOperation.SET)

    set_op.add_argument(
        "-p",
        "--path",
        action="store",
        default="",
        help=path_help,
    )

    set_op.add_argument(
        "input",
        type=str,
        nargs="?",
        metavar="input_file|value",
        help="Path to configuration file or configuration value.",
    )

    # DELETE operation
    delete_op = config_subparsers.add_parser(
        "delete", help="Delete given configuration property or list item at the given index."
    )
    delete_op.set_defaults(operation=ConfigOperation.DELETE)
    delete_op.add_argument(
        "-p",
        "--path",
        action="store",
        default="",
        help=path_help,
    )
    config_parser.set_defaults(command=ConfigCommand, command_args=ConfigCommandArgs)


class ConfigOperation(int, Enum):
    SET = 0
    DELETE = 1
    GET = 2


class ConfigCommand(KresClientCommand):
    def __init__(self, args: ConfigCommandArgs) -> None:
        self._socket = get_socket(args)
        self._args = args

    def run(self) -> None:
        new_config = None
        path = f"v1/config{self._args.path}"

        method: Literal["PUT", "GET", "DELETE"] = "PUT"
        if self._args.operation == ConfigOperation.GET:
            method = "GET"
        if self._args.operation == ConfigOperation.DELETE:
            method = "DELETE"

        if self._args.operation == ConfigOperation.SET:
            if self._args.input:
                try:
                    with Path(self._args.input).open() as f:
                        new_config = f.read()
                except FileNotFoundError:
                    new_config = self._args.input
            else:
                # use STDIN also when file is not specified
                new_config = input("Type new configuration value: ")

        body = DataFormat.JSON.dict_dump(try_to_parse(new_config)) if new_config else None
        response = request(self._socket, method, path, body)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

        if self._args.operation == ConfigOperation.GET and self._args.output_file:
            with self._args.output_file.open("w") as f:
                f.write(self._args.format.dict_dump(parse_json(response.body), indent=4))
            print(f"saved to: {self._args.output_file}")
        elif response.body:
            print(self._args.format.dict_dump(parse_json(response.body), indent=4))
