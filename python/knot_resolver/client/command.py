import argparse
from abc import ABC, abstractmethod  # pylint: disable=[no-name-in-module]
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
from urllib.parse import quote

from knot_resolver.constants import API_SOCK_FILE, CONFIG_FILE
from knot_resolver.datamodel.types import IPAddressPort
from knot_resolver.utils.modeling import parsing
from knot_resolver.utils.modeling.exceptions import DataValidationError
from knot_resolver.utils.requests import SocketDesc

T = TypeVar("T", bound=Type["Command"])

CompWords = Dict[str, Optional[str]]

_registered_commands: List[Type["Command"]] = []


def get_subparsers_words(subparser_actions: List[argparse.Action]) -> CompWords:
    words: CompWords = {}
    for action in subparser_actions:
        if isinstance(action, argparse._SubParsersAction) and action.choices:  # noqa: SLF001
            for choice, parser in action.choices.items():
                words[choice] = parser.description
        else:
            for opt in action.option_strings:
                words[opt] = action.help
    return words


def get_action_by_name(name: str, parser_actions: List[argparse.Action]) -> Optional[argparse.Action]:
    for action in parser_actions:
        if (action.choices and name in action.choices) or (action.option_strings and name in action.option_strings):
            return action
    return None


def get_subparser_command(subparser: argparse.ArgumentParser) -> "Command":
    defaults: Dict[str, Any] = subparser._defaults  # noqa: SLF001
    if "command" in defaults:
        return defaults["command"]
    raise ValueError(f"missing 'command' default for '{subparser.prog}' parser")


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


def get_socket_from_config(config: Path, optional_file: bool) -> Optional[SocketDesc]:
    try:
        with open(config, "r", encoding="utf8") as f:
            data = parsing.try_to_parse(f.read())
        mkey = "management"
        if mkey in data:
            management = data[mkey]
            if "unix-socket" in management:
                return SocketDesc(
                    f'http+unix://{quote(management["unix-socket"], safe="")}/',
                    f'Key "/management/unix-socket" in "{config}" file',
                )
            if "interface" in management:
                ip = IPAddressPort(management["interface"], object_path=f"/{mkey}/interface")
                return SocketDesc(
                    f"http://{ip.addr}:{ip.port}",
                    f'Key "/management/interface" in "{config}" file',
                )
        return None
    except ValueError as e:
        raise DataValidationError(*e.args) from e  # pylint: disable=no-value-for-parameter
    except OSError as e:
        if not optional_file:
            raise e
        return None


def determine_socket(namespace: argparse.Namespace) -> SocketDesc:
    # 1) socket from '--socket' argument
    if len(namespace.socket) > 0:
        return SocketDesc(namespace.socket[0], "--socket argument")

    socket: Optional[SocketDesc] = None
    # 2) socket from config file ('--config' argument)
    if len(namespace.config) > 0:
        socket = get_socket_from_config(namespace.config[0], False)
    # 3) socket from config file (default config file constant)
    else:
        socket = get_socket_from_config(CONFIG_FILE, True)

    if socket:
        return socket
    # 4) socket default
    return SocketDesc(str(API_SOCK_FILE), f'Default value "{API_SOCK_FILE}"')


class CommandArgs:
    def __init__(self, namespace: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
        self.namespace = namespace
        self.parser = parser
        self.subparser: argparse.ArgumentParser = namespace.subparser
        self.command: Type["Command"] = namespace.command

        self.socket: SocketDesc = determine_socket(namespace)


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
