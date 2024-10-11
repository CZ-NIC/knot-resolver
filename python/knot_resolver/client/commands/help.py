import argparse
from typing import Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, register_command


@register_command
class HelpCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    def run(self, args: CommandArgs) -> None:
        args.parser.print_help()

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = subparser.add_parser("help", help="show this help message and exit")
        return stop, HelpCommand
