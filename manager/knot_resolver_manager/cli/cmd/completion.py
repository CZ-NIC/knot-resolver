import argparse
from enum import Enum
from typing import Dict, List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command


class Shells(Enum):
    BASH = 0
    FISH = 1


@register_command
class CompletionCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        super().__init__(namespace, unknown_args)
        self.shell: Shells = namespace.shell
        self.unknown_args: List[str] = unknown_args

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        completion = subparser.add_parser("completion", help="commands auto-completion")

        shells_dest = "shell"
        shells = completion.add_mutually_exclusive_group()
        shells.add_argument("--bash", action="store_const", dest=shells_dest, const=Shells.BASH, default=Shells.BASH)
        shells.add_argument("--fish", action="store_const", dest=shells_dest, const=Shells.FISH)

        return completion, CompletionCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
        return {}

    def run(self, args: CommandArgs) -> None:
        parser = args.parser
        comp: Dict[str, Optional[str]] = {}

        top_comp: Dict[str, Optional[str]] = {}

        if parser._subparsers:
            for action in parser._subparsers._actions:
                if isinstance(action, argparse._SubParsersAction):
                    for sub in action._get_subactions():
                        top_comp[sub.dest] = sub.help
                else:
                    for s in action.option_strings:
                        top_comp[s] = action.help

            for arg in self.unknown_args:
                for action in parser._subparsers._actions:
                    if arg in action.option_strings:
                        continue
                    if isinstance(action, argparse._SubParsersAction) and arg in action.choices:
                        subparser: argparse.ArgumentParser = action.choices[arg]
                        command: Command = subparser._defaults["command"]

                        comp.update(command.completion(self.unknown_args, subparser))
                    else:
                        pass

        if self.shell == Shells.BASH:
            print(" ".join(comp))
        elif self.shell == Shells.FISH:
            pass
        else:
            pass
            # error
