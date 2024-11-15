import argparse
import sys
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple, Type

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


def _properties_words(props: Dict[str, Any]) -> CompWords:
    words: CompWords = {}
    for name, prop in props.items():
        words["/" + name] = prop["description"] if "description" in prop else None
    return words


# def _path_comp_words(node: str, nodes: List[str], props: Dict[str, Any]) -> CompWords:
#     i = nodes.index(node)
#     ln = len(nodes[i:])
#
#     # if node is last in path, return all possible words on thi level
#     if ln == 1:
#         return _properties_words(props)
#     # if node is valid
#     elif node in props:
#         node_schema = props[node]
#
#         if "anyOf" in node_schema:
#             for item in node_schema["anyOf"]:
#                 print(item)
#
#         elif "type" not in node_schema:
#             pass
#
#         elif node_schema["type"] == "array":
#             if ln > 2:
#                 # skip index for item in array
#                 return _path_comp_words(nodes[i + 2], nodes, node_schema["items"]["properties"])
#             if "enum" in node_schema["items"]:
#                 print(node_schema["items"]["enum"])
#             return {"0": "first array item", "-": "last array item"}
#         elif node_schema["type"] == "object":
#             if "additionalProperties" in node_schema:
#                 print(node_schema)
#             return _path_comp_words(nodes[i + 1], nodes, node_schema["properties"])
#         # return {}
#
#         # arrays/lists must be handled sparately
#         if node_schema["type"] == "array":
#             if ln > 2:
#                 # skip index for item in array
#                 return _path_comp_words(nodes[i + 2], nodes, node_schema["items"]["properties"])
#             return {"0": "first array item", "-": "last array item"}
#         return _path_comp_words(nodes[i + 1], nodes, node_schema["properties"])
#     else:
#         # if node is not last or valid, value error
#         raise ValueError(f"unknown config path node: {node}")


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

        get.add_argument(
            "-p",
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

        set.add_argument(
            "-p",
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
        delete.add_argument(
            "-p",
            "--path",
            help=path_help,
            action="store",
            type=str,
            default="",
        )

        return config, ConfigCommand

    @staticmethod
    def completion(parser: argparse.ArgumentParser, args: Optional[List[str]] = None, curr_index: int = 0) -> CompWords:
        if args is not None and (len(args) - curr_index) > 1 and args[-2] in ["-p", "--path"]:
            return _properties_words(KresConfig.json_schema()["properties"])

        return Command.completion(parser, args, curr_index)

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
