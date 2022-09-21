import argparse
import sys
from typing import List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command


@register_command
class ExitCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)

    def run(self, args: CommandArgs) -> None:
        sys.exit()

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> List[str]:
        return []

    @staticmethod
    def register_args_subparser(
        subparser: argparse._SubParsersAction[argparse.ArgumentParser],
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = subparser.add_parser("exit", help="exit kresctl")
        return stop, ExitCommand
