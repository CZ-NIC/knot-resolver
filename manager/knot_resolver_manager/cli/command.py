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


def get_help_command() -> Type["Command"]:
    for command in _registered_commands:
        if command.__name__ == "HelpCommand":
            return command
    raise ValueError("missing HelpCommand")


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
        if not hasattr(namespace, "command"):
            setattr(namespace, "command", get_help_command())

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
