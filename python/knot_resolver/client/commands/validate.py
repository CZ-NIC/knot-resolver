from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand
from knot_resolver.client.completion import CompletionWords, comp_get_words
from knot_resolver.constants import CONFIG_FILE
from knot_resolver.datamodel import KresConfig
from knot_resolver.datamodel.globals import Context, reset_global_validation_context, set_global_validation_context
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataParsingError, DataValidationError
from knot_resolver.utils.modeling.parsing import data_combine

if TYPE_CHECKING:
    import argparse


@dataclass(frozen=True)
class ValidateCommandArgs(KresClientArgs):
    strict: bool
    input_file: tuple[Path, ...]


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    validate_parser = subparser.add_parser("validate", help="Validates configuration in JSON or YAML format.")
    validate_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Enable strict rules during validation, e.g. paths/files existence and permissions.",
    )
    validate_parser.add_argument(
        "input_file",
        type=Path,
        nargs="*",
        default=(CONFIG_FILE,),
        help="File or combination of files with the declarative configuration in YAML or JSON format.",
    )
    validate_parser.set_defaults(command=ValidateCommand, command_args=ValidateCommandArgs)


class ValidateCommand(KresClientCommand):
    def __init__(self, args: ValidateCommandArgs) -> None:
        self._args = args

    def run(self) -> None:
        data: dict[str, Any] = {}
        try:
            for file in self._args.input_file:
                with file.open() as f:
                    raw = f.read()
                parsed = try_to_parse(raw)
                data = data_combine(data, parsed)

            set_global_validation_context(Context(Path(self._args.input_file[0]).parent, self._args.strict))
            KresConfig(data)
            reset_global_validation_context()
        except (FileNotFoundError, DataParsingError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        if not self._args.strict:
            print(
                "Basic validation was successful."
                "\nIf you want more strict validation, you can use the '--strict' switch."
                "\nDuring strict validation, the existence and access rights of paths are also checked."
                "\n\nHowever, if you are using an additional file system permission control mechanism,"
                "\nsuch as access control lists (ACLs), this validation will likely fail."
                "\nThis is because the validation runs under a different user/group than the resolver itself"
                "\nand attempts to access the configured paths directly."
            )

    @staticmethod
    def completion(args: list[str], parser: argparse.ArgumentParser) -> CompletionWords:
        return comp_get_words(args, parser)
