import argparse
import sys
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, register_command
from knot_resolver.datamodel import KresConfig
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json, try_to_parse
from knot_resolver.utils.requests import request


class Operations(Enum):
    SET = 0
    DELETE = 1
    GET = 2


def operation_to_method(operation: Operations) -> Literal["PUT", "GET", "DELETE"]:
    if operation == Operations.SET:
        return "PUT"
    elif operation == Operations.DELETE:
        return "DELETE"
    return "GET"


def generate_paths(data: Dict[str, Any], prefix: str = "/") -> CompWords:
    paths = {}

    if isinstance(data, dict):
        if "properties" in data.keys():
            for key in data["properties"]:
                current_path = f"{prefix}{key}"

                new_paths = generate_paths(data["properties"][key], current_path + "/")
                if new_paths != {}:
                    paths.update(new_paths)
                else:
                    paths[current_path] = None

        elif "items" in data.keys():
            if isinstance(data["items"], list):
                for item in data["items"]:
                    paths.update(generate_paths(item, prefix))
            else:
                paths.update(generate_paths(data["items"], prefix))

    return paths


@register_command
class ConfigCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.path: str = str(namespace.path) if hasattr(namespace, "path") else ""
        self.format: DataFormat = namespace.format if hasattr(namespace, "format") else DataFormat.JSON
        self.operation: Optional[Operations] = namespace.operation if hasattr(namespace, "operation") else None
        self.file: Optional[str] = namespace.file if hasattr(namespace, "file") else None

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        config = subparser.add_parser("config", help="Performs operations on the running resolver's configuration.")
        path_help = "Optional, path (JSON pointer, RFC6901) to the configuration resources. By default, the entire configuration is selected."

        config_subparsers = config.add_subparsers(help="operation type")

        # GET operation
        get = config_subparsers.add_parser("get", help="Get current configuration from the resolver.")
        get.set_defaults(operation=Operations.GET, format=DataFormat.YAML)

        get_path = get.add_mutually_exclusive_group()
        get_path.add_argument(
            "-p",
            help=path_help,
            action="store",
            type=str,
            default="",
        )
        get_path.add_argument(
            "--path",
            help=path_help,
            action="store",
            type=str,
            default="",
        )

        get.add_argument(
            "file",
            help="Optional, path to the file where to save exported configuration data. If not specified, data will be printed.",
            type=str,
            nargs="?",
        )

        get_formats = get.add_mutually_exclusive_group()
        get_formats.add_argument(
            "--json",
            help="Get configuration data in JSON format.",
            const=DataFormat.JSON,
            action="store_const",
            dest="format",
        )
        get_formats.add_argument(
            "--yaml",
            help="Get configuration data in YAML format, default.",
            const=DataFormat.YAML,
            action="store_const",
            dest="format",
        )

        # SET operation
        set = config_subparsers.add_parser("set", help="Set new configuration for the resolver.")
        set.set_defaults(operation=Operations.SET)

        set_path = set.add_mutually_exclusive_group()
        set_path.add_argument(
            "-p",
            help=path_help,
            action="store",
            type=str,
            default="",
        )
        set_path.add_argument(
            "--path",
            help=path_help,
            action="store",
            type=str,
            default="",
        )

        value_or_file = set.add_mutually_exclusive_group()
        value_or_file.add_argument(
            "file",
            help="Optional, path to file with new configuraion.",
            type=str,
            nargs="?",
        )
        value_or_file.add_argument(
            "value",
            help="Optional, new configuration value.",
            type=str,
            nargs="?",
        )

        # DELETE operation
        delete = config_subparsers.add_parser(
            "delete", help="Delete given configuration property or list item at the given index."
        )
        delete.set_defaults(operation=Operations.DELETE)
        delete_path = delete.add_mutually_exclusive_group()
        delete_path.add_argument(
            "-p",
            help=path_help,
            action="store",
            type=str,
            default="",
        )
        delete_path.add_argument(
            "--path",
            help=path_help,
            action="store",
            type=str,
            default="",
        )

        return config, ConfigCommand

    @staticmethod
    def completion(
        parser: argparse.ArgumentParser,
        args: Optional[List[str]] = None,
        curr_index: int = 0,
        argset: Optional[Set[str]] = None,
    ) -> CompWords:

        if args is None or len(args) == 0:
            return {}

        if args is not None and (len(args) - curr_index) > 1 and args[-2] in {"-p", "--path"}:
            paths = generate_paths(KresConfig.json_schema())
            result = {}
            for path in paths:
                if args[-1] in path:
                    a_count = args[-1].count("/") + 1
                    new_path = ""
                    for c in path:
                        new_path += c
                        if c == "/":
                            a_count -= 1
                            if a_count == 0:
                                break

                    result[new_path] = paths[path]

            return result

        if argset is None:
            argset = set(args)

        return Command.completion(parser, args, curr_index, argset)

    def run(self, args: CommandArgs) -> None:
        if not self.operation:
            args.subparser.print_help()
            sys.exit()

        new_config = None
        path = f"v1/config{self.path}"
        method = operation_to_method(self.operation)

        if self.operation == Operations.SET:
            if self.file:
                try:
                    with open(self.file, "r") as f:
                        new_config = f.read()
                except FileNotFoundError:
                    new_config = self.file
            else:
                # use STDIN also when file is not specified
                new_config = input("Type new configuration: ")

        body = DataFormat.JSON.dict_dump(try_to_parse(new_config)) if new_config else None
        response = request(args.socket, method, path, body)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

        if self.operation == Operations.GET and self.file:
            with open(self.file, "w") as f:
                f.write(self.format.dict_dump(parse_json(response.body), indent=4))
            print(f"saved to: {self.file}")
        elif response.body:
            print(self.format.dict_dump(parse_json(response.body), indent=4))
