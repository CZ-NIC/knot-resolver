import argparse
import sys
from typing import List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class StopCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/stop"
        response = request("POST", url)
        print(response)

        if response.status != 200:
            sys.exit(1)

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = subparser.add_parser(
            "stop", help="Tells the resolver to shutdown everthing. No process will run after this command."
        )
        return stop, StopCommand
