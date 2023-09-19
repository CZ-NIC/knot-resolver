import argparse
import os
from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TypeVar
from urllib.parse import quote

from knot_resolver_manager.constants import API_SOCK_ENV_VAR, CONFIG_FILE_ENV_VAR, DEFAULT_MANAGER_CONFIG_FILE
from knot_resolver_manager.datamodel.config_schema import DEFAULT_MANAGER_API_SOCK
from knot_resolver_manager.datamodel.types import FilePath, IPAddressPort
from knot_resolver_manager.utils.modeling import parsing
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError

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
        subparser.set_defaults(command=typ, subparser=subparser)


def get_socket_from_config(config: Path, optional_file: bool) -> Optional[str]:
    try:
        with open(config, "r") as f:
            data = parsing.try_to_parse(f.read())
        mkey = "management"
        if mkey in data:
            management = data[mkey]
            if "unix_socket" in management:
                return str(FilePath(management["unix_socket"], object_path=f"/{mkey}/unix-socket"))
            elif "interface" in management:
                ip = IPAddressPort(management["interface"], object_path=f"/{mkey}/interface")
                return f"http://{ip.addr}:{ip.port}"
        return None
    except ValueError as e:
        raise DataValidationError(*e.args)
    except OSError as e:
        if not optional_file:
            raise e
        return None


def determine_socket(namespace: argparse.Namespace) -> str:
    # 1) socket from 'kresctl --socket' argument
    if len(namespace.socket) > 0:
        return namespace.socket[0]

    config_path = os.getenv(CONFIG_FILE_ENV_VAR)
    socket_env = os.getenv(API_SOCK_ENV_VAR)

    socket: Optional[str] = None
    # 2) socket from config file ('kresctl --config' argument)
    if len(namespace.config) > 0:
        socket = get_socket_from_config(namespace.config[0], False)
    # 3) socket from config file (environment variable)
    elif config_path:
        socket = get_socket_from_config(Path(config_path), False)
    # 4) socket from environment variable
    elif socket_env:
        socket = socket_env
    # 5) socket from config file (default config file constant)
    else:
        socket = get_socket_from_config(DEFAULT_MANAGER_CONFIG_FILE, True)

    if socket:
        return socket
    # 6) socket default
    return DEFAULT_MANAGER_API_SOCK


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
