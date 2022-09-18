import argparse
from typing import Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command


class Shells:
    BASH = 0
    FISH = 1


@register_command
class CompletionCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        completion = parser.add_parser("completion", help="commands auto-completion")

        shells_dest = "shell"
        shells = completion.add_mutually_exclusive_group()
        shells.add_argument("--bash", action="store_const", dest=shells_dest, const=Shells.BASH, default=Shells.BASH)
        shells.add_argument("--fish", action="store_const", dest=shells_dest, const=Shells.FISH)

        completion.add_argument("values_to_complete", type=str, nargs="+", help="values to auto-complete")
        return completion, CompletionCommand

    def run(self, args: CommandArgs) -> None:
        pass
