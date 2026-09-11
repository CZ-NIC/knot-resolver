from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
    import argparse

    from knot_resolver.client.completion import CompletionWords


@dataclass(frozen=True)
class ReloadCommandArgs(KresClientArgs):
    force: bool


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    reload_parser = subparser.add_parser(
        "reload",
        help="Tells the resolver to reload YAML configuration file."
        " Old processes are replaced by new ones (with updated configuration) using rolling restarts."
        " So there will be no DNS service unavailability during reload operation.",
    )
    reload_parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Force a reload, even if the configuration hasn't changed.",
    )
    reload_parser.set_defaults(command=ReloadCommand, command_args=ReloadCommandArgs)


class ReloadCommand(KresClientCommand):
    def __init__(self, args: ReloadCommandArgs) -> None:
        self._socket = get_socket(args)
        self._args = args

    def run(self) -> None:
        response = request(self._socket, "POST", "reload/force" if self._args.force else "reload")

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def completion(_args: list[str], _parser: argparse.ArgumentParser) -> CompletionWords:
        return {}
