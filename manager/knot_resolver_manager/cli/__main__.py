import argparse
from abc import ABC
from typing import Optional

from knot_resolver_manager.cli import config, stop
from knot_resolver_manager.compat.dataclasses import dataclass


class Cmd(ABC):
    def __init__(self, ns: argparse.Namespace) -> None:
        pass

    def run(self, args: "Args") -> None:
        raise NotImplementedError()


class ConfigArgs(Cmd):
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__(ns)
        self.path: str = str(ns.path)
        self.replacement_value: Optional[str] = ns.new_value
        self.delete: bool = ns.delete
        self.stdin: bool = ns.stdin

    def run(self, args: "Args") -> None:
        config(args)


class StopArgs(Cmd):
    def run(self, args: "Args") -> None:
        stop(args)


@dataclass
class Args:
    socket: str
    command: Cmd  # union in the future


def parse_args() -> Args:
    # pylint: disable=redefined-outer-name

    parser = argparse.ArgumentParser("kresctl", description="CLI for controlling Knot Resolver")
    parser.add_argument(
        "-s",
        "--socket",
        action="store",
        type=str,
        help="manager API listen address",
        default="http+unix://%2Fvar%2Frun%2Fknot-resolver%2Fmanager.sock",
        nargs=1,
        required=True,
    )
    subparsers = parser.add_subparsers()

    config = subparsers.add_parser(
        "config", help="dynamically change configuration of a running resolver", aliases=["c", "conf"]
    )
    config.add_argument("path", type=str, help="which part of config should we work with")
    config.add_argument(
        "new_value",
        type=str,
        nargs="?",
        help="optional, what value should we set for the given path (JSON)",
        default=None,
    )
    config.add_argument("-d", "--delete", action="store_true", help="delete part of the config tree", default=False)
    config.add_argument("--stdin", help="read new config value on stdin", action="store_true", default=False)
    config.set_defaults(command_type=ConfigArgs)

    stop = subparsers.add_parser("stop", help="shutdown everything")
    stop.set_defaults(command_type=StopArgs)

    ns = parser.parse_args()
    return Args(socket=ns.socket[0], command=ns.command_type(ns))  # type: ignore[call-arg]


if __name__ == "__main__":
    _args = parse_args()
    _args.command.run(_args)
