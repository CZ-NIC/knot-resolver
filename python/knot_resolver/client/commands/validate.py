import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, comp_get_words, register_command
from knot_resolver.constants import CONFIG_FILE
from knot_resolver.datamodel import KresConfig
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataParsingError, DataValidationError
from knot_resolver.utils.modeling.parsing import data_combine
from knot_resolver.utils.modeling.validation_context import (
    Context,
    reset_global_validation_context,
    set_global_validation_context,
)


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
        validate.set_defaults(strict=False)
        validate.add_argument(
            "--strict",
            help="Enable strict rules during validation, e.g. paths/files existence and permissions.",
            action="store_true",
            dest="strict",
        )
        validate.add_argument(
            "input_file",
            type=str,
            nargs="*",
            help="File or combination of files with the declarative configuration in YAML or JSON format.",
            default=[CONFIG_FILE],
        )

        return validate, ValidateCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return comp_get_words(args, parser)

    def run(self, args: CommandArgs) -> None:
        data: Dict[str, Any] = {}
        try:
            for file in self.input_file:
                with open(file, "r") as f:
                    raw = f.read()
                parsed = try_to_parse(raw)
                data = data_combine(data, parsed)

            set_global_validation_context(Context(Path(self.input_file[0]).parent, self.strict))
            KresConfig(data)
            reset_global_validation_context()
        except (DataParsingError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        if not self.strict:
            print(
                "Basic validation was successful."
                "\nIf you want more strict validation, you can use the '--strict' switch."
                "\nDuring strict validation, the existence and access rights of paths are also checked."
                "\n\nHowever, if you are using an additional file system permission control mechanism,"
                "\nsuch as access control lists (ACLs), this validation will likely fail."
                "\nThis is because the validation runs under a different user/group than the resolver itself"
                "\nand attempts to access the configured paths directly."
            )
