import argparse
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.modeling.exceptions import DataParsingError


@register_command
class ConvertCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file

    @staticmethod
    def register_args_subparser(
        subparser: argparse._SubParsersAction[argparse.ArgumentParser],
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        convert = subparser.add_parser("convert", help="convert JSON/YAML configuration to Lua script")
        convert.add_argument(
            "input_file",
            type=str,
            help="JSON/YAML configuration input file",
        )

        convert.add_argument("--stdin", help="read new config value on stdin", action="store_true", default=False)
        convert.add_argument(
            "output_file",
            type=str,
            nargs="?",
            help="optional, output Lua script file",
            default=None,
        )

        return convert, ConvertCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> List[str]:
        return []

    def run(self, args: CommandArgs) -> None:

        with open(self.input_file, "r") as f:
            data = f.read()

        try:
            parsed = try_to_parse(data)
        except DataParsingError as e:
            print(e)
            return

        lua = KresConfig(parsed).render_lua()

        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(lua)
        else:
            print(lua)
