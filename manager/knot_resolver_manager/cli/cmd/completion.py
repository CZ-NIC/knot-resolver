import argparse
from enum import Enum
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command


class Shells(Enum):
    BASH = 0
    FISH = 1


def _parser_top_lvl_words(actions: List[argparse.Action]) -> CompWords:
    words: CompWords = {}

    for action in actions:
        if isinstance(action, argparse._SubParsersAction):
            for sub in action._get_subactions():
                words[sub.dest] = sub.help
        else:
            for s in action.option_strings:
                words[s] = action.help
    return words


def _subparser_words(comp_args: List[str], actions: List[argparse.Action]) -> Optional[CompWords]:
    for arg in comp_args:
        for action in actions:
            if isinstance(action, argparse._SubParsersAction) and arg in action.choices:
                subparser: argparse.ArgumentParser = action.choices[arg]
                command: Command = subparser._defaults["command"]

                subparser_args = comp_args[comp_args.index(arg) + 1 :]
                if subparser_args:
                    return command.completion(subparser_args, subparser)
    return None


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
        completion = subparser.add_parser("completion", help="commands auto-completion")
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
        comp: CompWords = {}

        for action in parser._actions:
            for opt in action.option_strings:
                comp[opt] = action.help
        return comp

    def run(self, args: CommandArgs) -> None:
        parser = args.parser
        words: CompWords = {}

        if parser._subparsers:
            subparser_words = _subparser_words(self.comp_args, parser._subparsers._actions)

            if subparser_words is None:
                # parser top level options/commands
                words = _parser_top_lvl_words(parser._subparsers._actions)
            else:
                # subparsers optons/commands
                words = subparser_words

        # print completion words
        # based on required bash/fish shell format
        if self.shell == Shells.BASH:
            print(" ".join(words))
        elif self.shell == Shells.FISH:
            # TODO: FISH completion implementation
            pass
        else:
            raise ValueError(f"unexpected value of {Shells}: {self.shell}")
