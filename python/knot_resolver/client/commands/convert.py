import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

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
class ConvertCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file
        self.strict: bool = namespace.strict
        self.type: str = namespace.type

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        convert = subparser.add_parser("convert", help="Converts JSON or YAML configuration to Lua script.")
        convert.set_defaults(strict=False)
        convert.add_argument(
            "--strict",
            help="Enable strict rules during validation, e.g. path/file existence and permissions.",
            action="store_true",
            dest="strict",
        )
        convert.add_argument(
            "--type", help="The type of Lua script to generate", choices=["worker", "policy-loader"], default="worker"
        )
        convert.add_argument(
            "-o",
            "--output",
            type=str,
            nargs="?",
            help="Optional, output file for converted configuration in Lua script. If not specified, converted configuration is printed.",
            dest="output_file",
            default=None,
        )
        convert.add_argument(
            "input_file",
            type=str,
            nargs="*",
            help="File or combination of files with configuration in YAML or JSON format.",
            default=[CONFIG_FILE],
        )
        return convert, ConvertCommand

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

            set_global_validation_context(Context(Path(Path(self.input_file[0]).parent), self.strict))
            if self.type == "worker":
                lua = KresConfig(data).render_kresd_lua()
            elif self.type == "policy-loader":
                lua = KresConfig(data).render_policy_loader_lua()
            else:
                raise ValueError(f"Invalid self.type={self.type}")
            reset_global_validation_context()
        except (DataParsingError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(lua)
        else:
            print(lua)
