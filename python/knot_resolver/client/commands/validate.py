import argparse
import sys
from pathlib import Path
from typing import List, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, register_command
from knot_resolver.datamodel import KresConfig
from knot_resolver.datamodel.globals import Context, reset_global_validation_context, set_global_validation_context
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataParsingError, DataValidationError


@register_command
class ValidateCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.strict: bool = namespace.strict

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        validate = subparser.add_parser("validate", help="Validates configuration in JSON or YAML format.")
        validate.set_defaults(strict=True)
        validate.add_argument(
            "--no-strict",
            help="Ignore strict rules during validation, e.g. path/file existence.",
            action="store_false",
            dest="strict",
        )
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
            set_global_validation_context(Context(Path(self.input_file).parent, self.strict))
            KresConfig(try_to_parse(data))
            reset_global_validation_context()
        except (DataParsingError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)
