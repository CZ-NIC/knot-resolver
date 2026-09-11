from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
    import argparse

    from knot_resolver.client.completion import CompletionWords


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    stop_parser = subparser.add_parser(
        "stop", help="Tells the resolver to shutdown everthing. No process will run after this command."
    )
    stop_parser.set_defaults(command=StopCommand, command_args=KresClientArgs)


class StopCommand(KresClientCommand):
    def __init__(self, args: KresClientArgs) -> None:
        self._socket = get_socket(args)

    def run(self) -> None:
        response = request(self._socket, "POST", "stop")

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def completion(_args: list[str], _parser: argparse.ArgumentParser) -> CompletionWords:
        return {}
