from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand
from knot_resolver.constants import CONFIG_FILE
from knot_resolver.datamodel import KresConfig
from knot_resolver.datamodel.globals import Context, reset_global_validation_context, set_global_validation_context
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataParsingError, DataValidationError
from knot_resolver.utils.modeling.parsing import data_combine

if TYPE_CHECKING:
    import argparse


@dataclass(frozen=True)
class ConvertCommandArgs(KresClientArgs):
    strict: bool
    type: Literal["worker", "policy-loader"]
    output_file: Path | None
    input_file: tuple[Path, ...]


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    convert_parser = subparser.add_parser("convert", help="Converts JSON or YAML configuration to Lua script.")
    convert_parser.add_argument(
        "--strict",
        action="store_true",
        default=False,
        help="Enable strict rules during validation, e.g. path/file existence and permissions.",
    )
    convert_parser.add_argument(
        "--type",
        choices=["worker", "policy-loader"],
        default="worker",
        help="The type of Lua script to generate",
    )
    convert_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        nargs="?",
        dest="output_file",
        help="Optional, output file for converted configuration in Lua script."
        " If not specified, converted configuration is printed.",
    )
    convert_parser.add_argument(
        "input_file",
        type=Path,
        nargs="*",
        default=(CONFIG_FILE,),
        help="File or combination of files with configuration in YAML or JSON format.",
    )
    convert_parser.set_defaults(command=ConvertCommand, command_args=ConvertCommandArgs)


class ConvertCommand(KresClientCommand):
    def __init__(self, args: ConvertCommandArgs) -> None:
        self._args = args

    def run(self) -> None:
        data: dict[str, Any] = {}
        try:
            for file in self._args.input_file:
                with file.open() as f:
                    raw = f.read()
                parsed = try_to_parse(raw)
                data = data_combine(data, parsed)

            set_global_validation_context(Context(Path(Path(self._args.input_file[0]).parent), self._args.strict))
            lua = KresConfig(data).render_kresd_lua()
            if self._args.type == "policy-loader":
                lua = KresConfig(data).render_policy_loader_lua()
            reset_global_validation_context()
        except (DataParsingError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        if self._args.output_file:
            with self._args.output_file.open("w") as f:
                f.write(lua)
        else:
            print(lua)
