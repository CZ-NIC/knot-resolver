import argparse
import sys
from typing import List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.modeling.exceptions import DataParsingError, DataValidationError


@register_command
class ValidateCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        validate = subparser.add_parser("validate", help="Validates configuration in JSON or YAML format.")
        validate.add_argument(
            "input_file",
            type=str,
            nargs="?",
            help="File with configuration in YAML or JSON format.",
            default=None,
        )

        return validate, ValidateCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        if self.input_file:
            with open(self.input_file, "r") as f:
                data = f.read()
        else:
            data = input("Type configuration to validate: ")

        try:
            KresConfig(try_to_parse(data))
        except (DataParsingError, DataValidationError) as e:
            print(e)
            sys.exit(1)
