import argparse
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class MetricsCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        self.file: Optional[str] = namespace.file

        super().__init__(namespace, unknown_args)

    @staticmethod
    def register_args_subparser(
        subparser: argparse._SubParsersAction[argparse.ArgumentParser],
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        metrics = subparser.add_parser("metrics", help="get prometheus metrics data")
        metrics.add_argument("file", help="optional, file to export metrics to", nargs="?", default=None)
        return metrics, MetricsCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> List[str]:
        return []

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/metrics"
        response = request("GET", url)

        if self.file and response.status == 200:
            with open(self.file, "w") as f:
                f.write(response.body)
        else:
            print(response)
