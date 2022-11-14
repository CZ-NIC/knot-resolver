import argparse
from typing import Optional, Tuple, Type

from typing_extensions import Literal

from knot_resolver_manager.cli import Command, TopLevelArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class ConfigCmd(Command):
    def __init__(self, ns: argparse.Namespace) -> None:
        super().__init__(ns)
        self.path: str = str(ns.path)
        self.replacement_value: Optional[str] = ns.new_value
        self.delete: bool = ns.delete
        self.stdin: bool = ns.stdin

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        config = parser.add_parser(
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

        return config, ConfigCmd

    def run(self, args: TopLevelArgs) -> None:
        if not self.path.startswith("/"):
            self.path = "/" + self.path

        method: Literal["GET", "PUT"] = "GET" if self.replacement_value is None else "PUT"
        url = f"{args.socket}/v1/config{self.path}"
        response = request(method, url, self.replacement_value)
        print(response)
