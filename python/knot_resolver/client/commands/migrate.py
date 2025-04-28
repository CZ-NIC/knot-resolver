import argparse
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, comp_get_words, register_command
from knot_resolver.utils.modeling.exceptions import DataParsingError
from knot_resolver.utils.modeling.parsing import DataFormat, try_to_parse


@register_command
class MigrateCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file
        self.output_format: DataFormat = namespace.output_format

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        migrate = subparser.add_parser("migrate", help="Migrates JSON or YAML configuration to the newer version.")

        migrate.set_defaults(output_format=DataFormat.YAML)
        output_formats = migrate.add_mutually_exclusive_group()
        output_formats.add_argument(
            "--json",
            help="Get migrated configuration data in JSON format.",
            const=DataFormat.JSON,
            action="store_const",
            dest="output_format",
        )
        output_formats.add_argument(
            "--yaml",
            help="Get migrated configuration data in YAML format, default.",
            const=DataFormat.YAML,
            action="store_const",
            dest="output_format",
        )

        migrate.add_argument(
            "input_file",
            type=str,
            help="File with configuration in YAML or JSON format.",
        )
        migrate.add_argument(
            "output_file",
            type=str,
            nargs="?",
            help="Optional, output file for migrated configuration in desired output format. If not specified, migrated configuration is printed.",
            default=None,
        )
        return migrate, MigrateCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return comp_get_words(args, parser)

    def run(self, args: CommandArgs) -> None:
        with open(self.input_file, "r") as f:
            data = f.read()

        try:
            parsed = try_to_parse(data)
        except DataParsingError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        dumped = self.output_format.dict_dump(parsed)
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(dumped)
        else:
            print(dumped)
