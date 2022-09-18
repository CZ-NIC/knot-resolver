import argparse
import json
from typing import Optional, Tuple, Type

import yaml

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.utils.modeling.parsing import ParsedTree, parse_json, parse_yaml


def _parse_data(input: str) -> Optional[ParsedTree]:
    try:
        return parse_yaml(input)
    except yaml.YAMLError:
        print(f"failed to parse input as YAML")
        try:
            return parse_json(input)
        except json.JSONDecodeError:
            print(f"failed to parse input as JSON")
            return None


@register_command
class ConvertCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        config = parser.add_parser("convert", help="convert JSON/YAML configuration to Lua script")
        config.add_argument(
            "input_file",
            type=str,
            help="JSON/YAML configuration input file",
        )

        config.add_argument("--stdin", help="read new config value on stdin", action="store_true", default=False)
        config.add_argument(
            "output_file",
            type=str,
            nargs="?",
            help="optional, output Lua script file",
            default=None,
        )

        return config, ConvertCommand

    def run(self, args: CommandArgs) -> None:

        with open(self.input_file, "r") as f:
            data = f.read()

        parsed = _parse_data(data)
        if not parsed:
            return

        lua = KresConfig(parsed).render_lua()

        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(lua)
        else:
            print(lua)
