import argparse
from enum import Enum
from typing import List, Tuple, Type

from knot_resolver.client.command import (
    Command,
    CommandArgs,
    CompWords,
    get_subparser_by_name,
    get_subparser_command,
    get_subparsers_words,
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
        self.space = namespace.space
        self.comp_args: List[str] = namespace.comp_args

        if self.space:
            self.comp_args.append("")

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        completion = subparser.add_parser(
            "completion",
            help="commands auto-completion",
        )
        completion.add_argument(
            "--space",
            help="space after last word, returns all possible folowing options",
            dest="space",
            action="store_true",
            default=False,
        )
        completion.add_argument(
            "comp_args",
            type=str,
            help="arguments to complete",
            nargs="*",
        )

        shells_dest = "shell"
        shells = completion.add_mutually_exclusive_group()
        shells.add_argument("--bash", action="store_const", dest=shells_dest, const=Shells.BASH, default=Shells.BASH)
        shells.add_argument("--fish", action="store_const", dest=shells_dest, const=Shells.FISH)

        return completion, CompletionCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return get_subparsers_words(parser._actions)  # noqa: SLF001

    def run(self, args: CommandArgs) -> None:
        subparsers = args.parser._subparsers  # noqa: SLF001
        words: CompWords = {}

        if subparsers:
            words = get_subparsers_words(subparsers._actions)  # noqa: SLF001

            uargs = iter(self.comp_args)
            for uarg in uargs:
                subparser = get_subparser_by_name(uarg, subparsers._actions)  # noqa: SLF001

                if subparser:
                    cmd: Command = get_subparser_command(subparser)
                    subparser_args = self.comp_args[self.comp_args.index(uarg) + 1 :]
                    if subparser_args or self.space:
                        words = cmd.completion(subparser_args, subparser)
                    break
                if uarg in ["-s", "--socket", "-c", "--config"]:
                    # if arg is socket config, skip next arg
                    next(uargs)
                    continue
                if uarg in words:
                    # uarg is valid (complete) arg, continue
                    continue
                else:
                    raise ValueError(f"unknown argument: {uarg}")

        # print completion words
        # based on required bash/fish shell format
        if self.shell == Shells.BASH:
            print(" ".join(words))
        elif self.shell == Shells.FISH:
            # TODO: FISH completion implementation
            pass
        else:
            raise ValueError(f"unexpected value of {Shells}: {self.shell}")
