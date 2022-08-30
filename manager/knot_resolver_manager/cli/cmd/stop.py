import argparse
from typing import Tuple, Type

from knot_resolver_manager.cli import Command, TopLevelArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class StopCmd(Command):
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__(ns)

    def run(self, args: TopLevelArgs) -> None:
        url = f"{args.socket}/stop"
        response = request("POST", url)
        print(response)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = parser.add_parser("stop", help="shutdown everything")
        return stop, StopCmd
