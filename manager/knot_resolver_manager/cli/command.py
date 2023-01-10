import argparse
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TypeVar
from urllib.parse import quote

T = TypeVar("T", bound=Type["Command"])

CompWords = Dict[str, Optional[str]]

_registered_commands: List[Type["Command"]] = []


def register_command(cls: T) -> T:
    _registered_commands.append(cls)
    return cls


def install_commands_parsers(parser: argparse.ArgumentParser) -> None:
    subparsers = parser.add_subparsers(help="command type")
    for command in _registered_commands:
        subparser, typ = command.register_args_subparser(subparsers)
        subparser.set_defaults(command=typ)


class CommandArgs:
    def __init__(self, namespace: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
        self.socket: str = namespace.socket[0]
        if Path(self.socket).exists():
            self.socket = f'http+unix://{quote(self.socket, safe="")}/'
        if self.socket.endswith("/"):
            self.socket = self.socket[:-1]

        self.command: Type["Command"] = namespace.command
        self.parser = parser
        self.namespace = namespace


class Command(ABC):
    @staticmethod
    @abstractmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        raise NotImplementedError()

    @abstractmethod
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__()

    @abstractmethod
    def run(self, args: CommandArgs) -> None:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        raise NotImplementedError()


# def parser_words(actions: List[argparse.Action]) -> CompWords:
#     words: CompWords = {}
#     for action in actions:
#         if isinstance(action, argparse._SubParsersAction):  # pylint: disable=W0212
#             for sub in action._get_subactions():  # pylint: disable=W0212
#                 words[sub.dest] = sub.help
#         elif isinstance(
#             action, (argparse._StoreConstAction, argparse._StoreAction, argparse._HelpAction)  # pylint: disable=W0212
#         ):  # pylint: disable=W0212
#             for s in action.option_strings:
#                 words[s] = action.help
#     return words


# def subparser_by_name(subparser_name: str, actions: List[argparse.Action]) -> Optional[argparse.ArgumentParser]:
#     for action in actions:
#         if isinstance(action, argparse._SubParsersAction) and subparser_name in action.choices:  # pylint: disable=W0212
#             return action.choices[subparser_name]
#     return None


# def subparser_command(subparser: argparse.ArgumentParser) -> Command:
#     return subparser._defaults["command"]  # pylint: disable=W0212
