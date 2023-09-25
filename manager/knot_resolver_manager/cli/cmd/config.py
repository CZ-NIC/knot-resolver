import argparse
import json
import sys
from enum import Enum
from typing import List, Optional, Tuple, Type

import yaml
from typing_extensions import Literal

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.requests import request


class Operations(Enum):
    SET = 0
    DELETE = 1
    GET = 2


class Formats(Enum):
    JSON = 0
    YAML = 1


def operation_to_method(operation: Operations) -> Literal["PUT", "GET", "DELETE"]:
    if operation == Operations.SET:
        return "PUT"
    elif operation == Operations.DELETE:
        return "DELETE"
    return "GET"


def reformat(json_str: str, req_format: Formats) -> str:
    d = json.loads(json_str)
    if req_format == Formats.YAML:
        return yaml.dump(d, indent=4)
    return json.dumps(d, indent=4)


def json_dump(yaml_or_json_str: str) -> str:
    return json.dumps(try_to_parse(yaml_or_json_str))


# def _properties_words(props: Dict[str, Any]) -> CompWords:
#     words: CompWords = {}
#     for name, prop in props.items():
#         words[name] = prop["description"] if "description" in prop else None
#     return words


# def _path_comp_words(node: str, nodes: List[str], props: Dict[str, Any]) -> CompWords:
#     i = nodes.index(node)
#     ln = len(nodes[i:])

#     # if node is last in path, return all possible words on thi level
#     if ln == 1:
#         return _properties_words(props)
#     # if node is valid
#     elif node in props:
#         node_schema = props[node]

#         if "anyOf" in node_schema:
#             for item in node_schema["anyOf"]:
#                 print(item)

#         elif "type" not in node_schema:
#             pass

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
#         return {}

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
        self.format: Formats = namespace.format if hasattr(namespace, "format") else Formats.JSON
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
        get.set_defaults(operation=Operations.GET)

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
            help="Get configuration data in JSON format, default.",
            const=Formats.JSON,
            action="store_const",
            dest="format",
        )
        get_formats.add_argument(
            "--yaml",
            help="Get configuration data in YAML format.",
            const=Formats.YAML,
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

        set_formats = set.add_mutually_exclusive_group()
        set_formats.add_argument(
            "--json",
            help="Set configuration data in JSON format, default.",
            const=Formats.JSON,
            action="store_const",
            dest="format",
        )
        set_formats.add_argument(
            "--yaml",
            help="Set configuration data in YAML format.",
            const=Formats.YAML,
            action="store_const",
            dest="format",
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
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        # words = parser_words(parser._actions)  # pylint: disable=W0212

        # for arg in args:
        #     if arg in words:
        #         continue
        #     elif arg.startswith("-"):
        #         return words
        #     elif arg == args[-1]:
        #         config_path = arg[1:].split("/") if arg.startswith("/") else arg.split("/")
        #         schema_props: Dict[str, Any] = KresConfig.json_schema()["properties"]
        #         return _path_comp_words(config_path[0], config_path, schema_props)
        #     else:
        #         break
        return {}

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

        response = request(args.socket, method, path, json_dump(new_config) if new_config else None)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

        if self.operation == Operations.GET and self.file:
            with open(self.file, "w") as f:
                f.write(reformat(response.body, self.format))
            print(f"saved to: {self.file}")
        elif response.body:
            print(reformat(response.body, self.format))
