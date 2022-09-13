import argparse
import json
from typing import Optional, Tuple, Type

import yaml
from typing_extensions import Literal

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.utils.requests import request


class Operations:
    SET = 0
    DELETE = 1
    GET = 2


class Formats:
    JSON = 0
    YAML = 1


Methods = Literal["POST", "GET", "DELETE"]


def _method_map(op: Operations) -> Methods:
    if op == Operations.SET:
        return "POST"
    elif op == Operations.DELETE:
        return "DELETE"
    elif op == Operations.GET:
        return "GET"
    else:
        pass


def _format(data: Optional[str], req_format: Formats) -> Optional[str]:
    if not data:
        return None

    dic = {}
    try:
        dic = json.loads(data)
    except json.JSONDecodeError:
        try:
            dic = yaml.load(data)
        except yaml.YAMLError:
            return data

    if req_format == Formats.JSON:
        return json.dumps(dic, indent=4)
    elif req_format == Formats.YAML:
        return yaml.dump(dic, indent=4)
    return None


@register_command
class ConfigCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.path: str = str(namespace.path)
        self.value_or_file: Optional[str] = namespace.value_or_file
        self.operation: Operations = namespace.operation
        self.format: Formats = namespace.format
        self.stdin: bool = namespace.stdin

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        config = parser.add_parser("config", help="change configuration of a running resolver")
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

    def run(self, args: CommandArgs) -> None:
        if not self.path.startswith("/"):
            self.path = "/" + self.path

        new_config = None
        url = f"{args.socket}/v1/config{self.path}"
        method = _method_map(self.operation)

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

        response = request(method, url, _format(new_config, Formats.JSON))
        print(f"status: {response.status}")

        if self.operation == Operations.GET and self.value_or_file:
            with open(self.value_or_file, "w") as f:
                f.write(_format(response.body, self.format))
            print(f"response body saved to: {self.value_or_file}")
        else:
            print(_format(response.body, self.format))
