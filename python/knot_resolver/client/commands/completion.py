import argparse
from enum import Enum
from typing import List, Optional, Tuple, Type

from knot_resolver.client.command import (
    Command,
    CommandArgs,
    CompWords,
    get_action_by_name,
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
        self.args: List[str] = namespace.args

        if self.space:
            self.args.append("")

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

        shells_dest = "shell"
        shells = completion.add_mutually_exclusive_group()
        shells.add_argument("--bash", action="store_const", dest=shells_dest, const=Shells.BASH, default=Shells.BASH)
        shells.add_argument("--fish", action="store_const", dest=shells_dest, const=Shells.FISH)

        completion.add_argument("--args", help="arguments to complete", nargs=argparse.REMAINDER, default=[])

        return completion, CompletionCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return get_subparsers_words(parser._actions)  # noqa: SLF001

    def run(self, args: CommandArgs) -> None:  # noqa: PLR0912
        subparsers = args.parser._subparsers  # noqa: SLF001
        words: CompWords = {}

        if subparsers:
            words = get_subparsers_words(subparsers._actions)  # noqa: SLF001

            args_iter = iter(self.args)
            for arg in args_iter:
                action: Optional[argparse.Action] = get_action_by_name(arg, subparsers._actions)  # noqa: SLF001

                # if action is SubParserAction; complete using the command
                if isinstance(action, argparse._SubParsersAction) and arg in action.choices:  # noqa: SLF001
                    # remove from words
                    for choice in action.choices:
                        del words[choice]

                    subparser = action.choices[arg]
                    cmd = get_subparser_command(subparser)

                    nargs = len(self.args)
                    index = self.args.index(arg) + 1
                    # check that index is not out of args length
                    if index > nargs:
                        break

                    # complete using the command
                    words = cmd.completion(self.args[index:], subparser)
                    break

                # if action is StoreAction; skip number of arguments
                if isinstance(action, argparse._StoreAction) and arg in action.option_strings:  # noqa: SLF001
                    # remove from words
                    for option_string in action.option_strings:
                        del words[option_string]

                    if action.nargs and isinstance(action.nargs, int):
                        for _ in range(action.nargs):
                            next(args_iter)
                    continue

                # remove other options from words
                if action and action.option_strings:
                    for option_string in action.option_strings:
                        del words[option_string]

                # if 'arg' is not found in actions
                # there is nothing to complete
                if not action:
                    break

        # print completion words
        # based on required bash/fish shell format
        if self.shell == Shells.BASH:
            print(" ".join(words))
        elif self.shell == Shells.FISH:
            # TODO: FISH completion implementation
            pass
        else:
            raise ValueError(f"unexpected value of {Shells}: {self.shell}")
