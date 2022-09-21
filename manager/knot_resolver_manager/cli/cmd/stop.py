import argparse
from typing import List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class StopCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/stop"
        response = request("POST", url)
        print(response)

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> List[str]:
        return []

    @staticmethod
    def register_args_subparser(
        subparser: argparse._SubParsersAction[argparse.ArgumentParser],
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = subparser.add_parser("stop", help="shutdown everything")
        return stop, StopCommand
