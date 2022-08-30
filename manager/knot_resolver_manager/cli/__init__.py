import argparse
import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Tuple, Type, TypeVar, cast
from urllib.parse import quote

from typing_extensions import Protocol


class TopLevelArgs:
    def __init__(self, ns: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
        self.socket: str = ns.socket[0]
        if Path(self.socket).exists():
            self.socket = f'http+unix://{quote(self.socket, safe="")}/'
        if self.socket.endswith("/"):
            self.socket = self.socket[:-1]

        self.command: Type["Command"] = ns.first_level_command
        self.parser = parser
        self.namespace = ns


class Command(ABC):
    @staticmethod
    @abstractmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        raise NotImplementedError()

    @abstractmethod
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__()

    @abstractmethod
    def run(self, args: TopLevelArgs) -> None:
        raise NotImplementedError()


_registered_commands: List[Type[Command]] = []


T = TypeVar("T", bound=Type[Command])


def register_command(cls: T) -> T:
    _registered_commands.append(cls)
    return cls


def install_subcommand_parsers(arg: argparse.ArgumentParser) -> None:
    subparsers = arg.add_subparsers()
    for subcommand in _registered_commands:
        parser, tp = subcommand.register_args_subparser(subparsers)
        parser.set_defaults(first_level_command=tp)


def create_main_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser("kresctl", description="CLI for controlling Knot Resolver")
    parser.add_argument(
        "-s",
        "--socket",
        action="store",
        type=str,
        help="manager API listen address",
        default=["http+unix://%2Fvar%2Frun%2Fknot-resolver%2Fmanager.sock"],  # FIXME
        nargs=1,
        required=False,
    )
    return parser


class SubcommandProtocol(Protocol):
    @staticmethod
    def register_command(c: T) -> T:
        raise NotImplementedError()


def register_subcommand(
    name: str, help: Optional[str] = None  # pylint: disable=redefined-builtin
) -> SubcommandProtocol:
    class Subcommand(Command):
        subcommands: List[Type[Command]] = []

        def __init__(self, ns: argparse.Namespace) -> None:
            super().__init__(ns)
            self.subcommand: Type[Command] = ns.subcommand

        @staticmethod
        def register_args_subparser(
            parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
        ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
            subcmd = parser.add_parser(name, help=help)
            subparsers = subcmd.add_subparsers()
            for cmd in Subcommand.subcommands:
                p, tp = cmd.register_args_subparser(subparsers)
                p.set_defaults(subcommand=tp)

            return subcmd, Subcommand

        @staticmethod
        def register_command(c: T) -> T:
            Subcommand.subcommands.append(c)
            return c

        def run(self, args: TopLevelArgs) -> None:
            cmd = self.subcommand(args.namespace)
            cmd.run(args)

    register_command(Subcommand)
    return cast(SubcommandProtocol, Subcommand)


def autoimport_commands() -> None:
    for _loader, module_name, _is_pkg in pkgutil.walk_packages(
        (f"{s}/cmd" for s in __path__), prefix="knot_resolver_manager.cli.cmd."
    ):
        importlib.import_module(module_name)


def main() -> None:
    autoimport_commands()
    parser = create_main_arg_parser()
    install_subcommand_parsers(parser)
    ns = parser.parse_args()

    toplevel = TopLevelArgs(ns, parser)
    second = toplevel.command(ns)
    second.run(toplevel)
