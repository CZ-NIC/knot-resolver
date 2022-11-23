import argparse
import json
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

import yaml
from typing_extensions import Literal

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.requests import request


class Operations(Enum):
    SET = 0
    DELETE = 1
    GET = 2


class Formats(Enum):
    JSON = 0
    YAML = 1


def operation_to_method(operation: Operations) -> Literal["POST", "GET", "DELETE"]:
    if operation == Operations.SET:
        return "POST"
    elif operation == Operations.DELETE:
        return "DELETE"

    return "GET"


def reformat(data: str, req_format: Formats) -> str:
    dict = try_to_parse(data).to_raw()

    if req_format == Formats.YAML:
        return yaml.dump(dict, indent=4)
    return json.dumps(dict, indent=4)


def properties_comp(props: Dict[str, Any]) -> Dict[str, Optional[str]]:
    comp: Dict[str, Optional[str]] = {}
    for name, prop in props.items():
        comp[name] = prop["description"] if "description" in prop else None
    return comp


def node_comp(nodes: List[str], props: Dict[str, Any]) -> Dict[str, Optional[str]]:

    if len(nodes) > 1 and nodes[0] in props:
        prop = props[nodes[0]]
        if "properties" in prop:
            return node_comp(nodes[1:], prop["properties"])
        else:
            return {}
    else:
        return properties_comp(props)


def config_path_comp(path: str) -> Dict[str, Optional[str]]:
    nodes = path[1:].split("/") if path.startswith("/") else path.split("/")
    properties: Dict[str, Any] = KresConfig.json_schema()["properties"]
    return node_comp(nodes, properties)


def subparser_comp(parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
    comp: Dict[str, Optional[str]] = {}

    for action in parser._actions:
        if isinstance(action, (argparse._StoreConstAction, argparse._HelpAction)):
            for s in action.option_strings:
                comp[s] = action.help
    return comp


@register_command
class ConfigCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)
        self.path: str = str(namespace.path)
        self.value_or_file: Optional[str] = namespace.value_or_file
        self.operation: Operations = namespace.operation
        self.format: Formats = namespace.format
        self.stdin: bool = namespace.stdin

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        config = subparser.add_parser("config", help="change configuration of a running resolver")
        config.add_argument(
            "path",
            type=str,
            help="path to the specify part of the configuration to work with",
        )

        config.add_argument("--stdin", help="read new config value on stdin", action="store_true", default=False)
        config.add_argument(
            "value_or_file",
            type=str,
            nargs="?",
            help="optional, new configuration values, path to the file with new values or path to the file to export data",
            default=None,
        )

        op_dest = "operation"
        operations = config.add_mutually_exclusive_group()
        operations.add_argument(
            "-s",
            "--set",
            help="set new configuration",
            action="store_const",
            dest=op_dest,
            const=Operations.SET,
            default=Operations.SET,
        )
        operations.add_argument(
            "-d",
            "--delete",
            help="delete configuration",
            action="store_const",
            dest=op_dest,
            const=Operations.DELETE,
        )
        operations.add_argument(
            "-g", "--get", help="get configuration", action="store_const", dest=op_dest, const=Operations.GET
        )

        fm_dest = "format"
        formats = config.add_mutually_exclusive_group()
        formats.add_argument(
            "--json",
            help="JSON configuration format",
            action="store_const",
            dest=fm_dest,
            const=Formats.JSON,
            default=Formats.JSON,
        )
        formats.add_argument(
            "--yaml", help="YAML configuration format", action="store_const", dest=fm_dest, const=Formats.YAML
        )

        return config, ConfigCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
        top_comp = subparser_comp(parser)

        for arg in args:
            if arg in top_comp:
                continue
            elif arg.startswith("-"):
                return top_comp
            elif arg == args[-1]:
                return config_path_comp(arg)
            else:
                break
        return {}

    def run(self, args: CommandArgs) -> None:
        if not self.path.startswith("/"):
            self.path = "/" + self.path

        new_config = None
        url = f"{args.socket}/v1/config{self.path}"
        method = operation_to_method(self.operation)

        if self.operation == Operations.SET:
            # use STDIN also when value_or_file is not specified
            if self.stdin or not self.value_or_file:
                new_config = input("Type new configuration: ")
            else:
                try:
                    with open(self.value_or_file, "r") as f:
                        new_config = f.read()
                except FileNotFoundError:
                    new_config = self.value_or_file

        response = request(method, url, reformat(new_config, Formats.JSON) if new_config else None)
        print(f"status: {response.status}")

        if self.operation == Operations.GET and self.value_or_file and response.status == 200:
            with open(self.value_or_file, "w") as f:
                f.write(reformat(response.body, self.format))
            print(f"saved to: {self.value_or_file}")
        else:
            print(reformat(response.body, self.format))
