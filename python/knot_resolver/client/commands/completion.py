from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import Enum

from knot_resolver.client.args import KresClientArgs, get_client_parser
from knot_resolver.client.command import KresClientCommand
from knot_resolver.client.completion import CompletionWords, comp_get_words


@dataclass(frozen=True)
class CompletionCommandArgs(KresClientArgs):
    shell: Shell
    args: list[str]


class Shell(int, Enum):
    BASH = 0
    FISH = 1


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    completion_parser = subparser.add_parser(
        "completion",
        help="commands auto-completion",
    )
    shell_dest = "shell"
    shell = completion_parser.add_mutually_exclusive_group()
    shell.add_argument("--bash", action="store_const", dest=shell_dest, const=Shell.BASH, default=Shell.BASH)
    shell.add_argument("--fish", action="store_const", dest=shell_dest, const=Shell.FISH)

    completion_parser.add_argument("--args", help="arguments to complete", nargs=argparse.REMAINDER, default=[])
    completion_parser.set_defaults(command=CompletionCommand, command_args=CompletionCommandArgs)


class CompletionCommand(KresClientCommand):
    def __init__(self, args: CompletionCommandArgs) -> None:
        self._args = args

    def run(self) -> None:
        parser = get_client_parser()
        words: CompletionWords = {}

        if parser:
            words = comp_get_words(self._args.args, parser)

        # print completion words
        # based on required bash/fish shell format
        if self._args.shell == Shell.BASH:
            print(" ".join(words))
        if self._args.shell == Shell.FISH:
            # TODO: FISH completion implementation
            pass

    @staticmethod
    def completion(args: list[str], parser: argparse.ArgumentParser) -> CompletionWords:
        return comp_get_words(args, parser)
