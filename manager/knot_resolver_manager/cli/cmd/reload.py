import argparse
import sys
from typing import List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class ReloadCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        reload = subparser.add_parser(
            "reload",
            help="Tells the resolver to reload YAML configuration file."
            " Old processes are replaced by new ones (with updated configuration) using rolling restarts."
            " So there will be no DNS service unavailability during reload operation.",
        )

        return reload, ReloadCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        response = request(args.socket, "POST", "reload")

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)
