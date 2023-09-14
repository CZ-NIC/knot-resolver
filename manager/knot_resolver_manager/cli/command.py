import argparse
import os
from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TypeVar
from urllib.parse import quote

from knot_resolver_manager.constants import CONFIG_FILE_ENV_VAR
from knot_resolver_manager.utils.modeling import parsing

T = TypeVar("T", bound=Type["Command"])

CompWords = Dict[str, Optional[str]]

_registered_commands: List[Type["Command"]] = []

# FIXME ostava: Someone put a FIXME on this value without an explanation, so who knows what is wrong with it?
DEFAULT_SOCKET = "http+unix://%2Fvar%2Frun%2Fknot-resolver%2Fmanager.sock"


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
        subparser.set_defaults(command=typ, subparser=subparser)


class CommandArgs:
    def __init__(self, namespace: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
        self.namespace = namespace
        self.parser = parser
        self.subparser: argparse.ArgumentParser = namespace.subparser
        self.command: Type["Command"] = namespace.command

        config_env = os.getenv(CONFIG_FILE_ENV_VAR)
        if len(namespace.socket) == 0 and len(namespace.config) == 0 and config_env is not None:
            namespace.config = [config_env]

        self.socket: str = DEFAULT_SOCKET
        if len(namespace.socket) > 0:
            self.socket = namespace.socket[0]
        elif len(namespace.config) > 0:
            with open(namespace.config[0], "r") as f:
                config = parsing.try_to_parse(f.read())
            if "management" in config:
                management = config["management"]
                if "unix_socket" in management:
                    self.socket = management["unix_socket"]
                elif "interface" in management:
                    split = management["interface"].split("@")
                    host = split[0]
                    port = split[1] if len(split) >= 2 else 80
                    self.socket = f"http://{host}:{port}"

        if Path(self.socket).exists():
            self.socket = f'http+unix://{quote(self.socket, safe="")}/'
        if self.socket.endswith("/"):
            self.socket = self.socket[:-1]


class Command(ABC):
    @staticmethod
    @abstractmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        raise NotImplementedError()

    @abstractmethod
    def __init__(self, namespace: argparse.Namespace) -> None:  # pylint: disable=[unused-argument]
        super().__init__()

    @abstractmethod
    def run(self, args: CommandArgs) -> None:
        raise NotImplementedError()

    @staticmethod
    @abstractmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        raise NotImplementedError()
