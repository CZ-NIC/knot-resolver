import argparse
import os
from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TypeVar
from urllib.parse import quote

from knot_resolver_manager.constants import DEFAULT_MANAGER_CONFIG_FILE, CONFIG_FILE_ENV_VAR
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


def get_socket_from_config(config: Path, optional_file: bool) -> Optional[str]:
    try:
        with open(config, "r") as f:
            data = parsing.try_to_parse(f.read())
        if "management" in data:
            management = data["management"]
            if "unix_socket" in management:
                return management["unix_socket"]
            elif "interface" in management:
                split = management["interface"].split("@")
                host = split[0]
                port = split[1] if len(split) >= 2 else 80
                return f"http://{host}:{port}"
        return None
    except OSError as e:
        if not optional_file:
            raise e
        return None


def determine_socket(namespace: argparse.Namespace) -> str:
    if len(namespace.socket) > 0:
        return namespace.socket[0]

    socket: Optional[str] = None
    if len(namespace.config) > 0:
        socket = get_socket_from_config(namespace.config[0], False)
        if socket is not None:
            return socket
    else:
        config_env = os.getenv(CONFIG_FILE_ENV_VAR)
        if config_env is not None:
            socket = get_socket_from_config(Path(config_env), False)
            if socket is not None:
                return socket
        else:
            socket = get_socket_from_config(DEFAULT_MANAGER_CONFIG_FILE, True)
            if socket is not None:
                return socket

    return DEFAULT_SOCKET


class CommandArgs:
    def __init__(self, namespace: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
        self.namespace = namespace
        self.parser = parser
        self.subparser: argparse.ArgumentParser = namespace.subparser
        self.command: Type["Command"] = namespace.command

        self.socket: str = determine_socket(namespace)

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
