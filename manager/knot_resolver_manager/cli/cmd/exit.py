import argparse
import sys
from typing import Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command


@register_command
class ExitCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    def run(self, args: CommandArgs) -> None:
        sys.exit()

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = parser.add_parser("exit", help="exit kresctl")
        return stop, ExitCommand
