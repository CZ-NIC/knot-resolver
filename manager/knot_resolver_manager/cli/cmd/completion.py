import argparse
from typing import Dict, Optional, Tuple, Type

from knot_resolver_manager.cli import Command, TopLevelArgs, register_subcommand


def _list_subcommands(parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
    try:
        result: Dict[str, Optional[str]] = {}
        for action in parser._subparsers._actions:  # type: ignore
            if isinstance(action, argparse._SubParsersAction):
                for subact in action._get_subactions():
                    name = subact.dest
                    help = subact.help
                    result[name] = help
        return result
    except Exception:
        # if it fails, abort
        return {}


Completions = register_subcommand("completion", help="shell completions")


@Completions.register_command
class FishCompletion(Command):
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__(ns)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        fcpl = parser.add_parser("fish", help="completion for fish")
        return fcpl, FishCompletion

    def run(self, args: TopLevelArgs) -> None:
        for cmd, help in _list_subcommands(args.parser).items():
            print(f"complete -c kresctl -a '{cmd}'", end="")
            if help is not None:
                print(f" -d '{help}'")
            else:
                print()


@Completions.register_command
class BashCompletion(Command):
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__(ns)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        fcpl = parser.add_parser("bash", help="completion for bash")
        return fcpl, BashCompletion

    def run(self, args: TopLevelArgs) -> None:
        raise NotImplementedError
