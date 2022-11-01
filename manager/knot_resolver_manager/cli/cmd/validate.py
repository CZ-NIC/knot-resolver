import argparse
from typing import Dict, List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.datamodel import KresConfig
from knot_resolver_manager.utils.modeling import try_to_parse
from knot_resolver_manager.utils.modeling.exceptions import DataParsingError, DataValidationError


@register_command
class ValidateCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)
        self.input_file: str = namespace.input_file

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        validate = subparser.add_parser("validate", help="validate JSON/YAML configuration")
        validate.add_argument(
            "input_file",
            type=str,
            nargs="?",
            help="JSON/YAML configuration input file",
            default=None,
        )

        return validate, ValidateCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
        return {}

    def run(self, args: CommandArgs) -> None:

        if self.input_file:
            with open(self.input_file, "r") as f:
                data = f.read()
        else:
            data = input("Type new configuration: ")

        try:
            KresConfig(try_to_parse(data))
            print("config is valid")
        except (DataParsingError, DataValidationError) as e:
            print(e)
