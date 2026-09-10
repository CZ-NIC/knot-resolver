from __future__ import annotations

from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs, get_client_parser
from knot_resolver.client.command import KresClientCommand

if TYPE_CHECKING:
    import argparse


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    help_parser = subparser.add_parser("help", help="show this help message and exit")
    help_parser.set_defaults(command=HelpCommand, command_args=KresClientArgs)


class HelpCommand(KresClientCommand):
    def __init__(self, _args: KresClientArgs) -> None:
        pass

    def run(self) -> None:
        parser = get_client_parser()
        parser.print_help()
