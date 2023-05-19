import argparse
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.modeling.exceptions import DataParsingError, DataValidationError


@register_command
class ConvertCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        convert = subparser.add_parser("convert", help="Converts JSON or YAML configuration to Lua script.")
        convert.add_argument(
            "input_file",
            type=str,
            help="File with configuration in YAML or JSON format.",
        )

        convert.add_argument(
            "output_file",
            type=str,
            nargs="?",
            help="Optional, output file for converted configuration in Lua script. If not specified, converted configuration is printed.",
            default=None,
        )

        return convert, ConvertCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        with open(self.input_file, "r") as f:
            data = f.read()

        try:
            parsed = try_to_parse(data)
            lua = KresConfig(parsed).render_lua()
        except (DataParsingError, DataValidationError) as e:
            print(e)
            sys.exit(1)

        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(lua)
        else:
            print(lua)
