# noqa: INP001
import argparse
from enum import Enum
from typing import List, Tuple, Type

from knot_resolver.client.command import (
    Command,
    CommandArgs,
    CompWords,
    comp_get_words,
    register_command,
)


class Shells(Enum):
    BASH = 0
    FISH = 1


@register_command
class CompletionCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.shell: Shells = namespace.shell
        self.args: List[str] = namespace.args
        if namespace.extra is not None:
            self.args.append("--")

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        completion = subparser.add_parser(
            "completion",
            help="commands auto-completion",
        )

        shells_dest = "shell"
        shells = completion.add_mutually_exclusive_group()
        shells.add_argument("--bash", action="store_const", dest=shells_dest, const=Shells.BASH, default=Shells.BASH)
        shells.add_argument("--fish", action="store_const", dest=shells_dest, const=Shells.FISH)

        completion.add_argument("--args", help="arguments to complete", nargs=argparse.REMAINDER, default=[])

        return completion, CompletionCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return comp_get_words(args, parser)

    def run(self, args: CommandArgs) -> None:  # noqa: PLR0912
        words: CompWords = {}

        parser = args.parser
        if parser:
            words = comp_get_words(self.args, args.parser)

        # print completion words
        # based on required bash/fish shell format
        if self.shell == Shells.BASH:
            print(" ".join(words))
        elif self.shell == Shells.FISH:
            # TODO: FISH completion implementation
            pass
        else:
            raise ValueError(f"unexpected value of {Shells}: {self.shell}")
