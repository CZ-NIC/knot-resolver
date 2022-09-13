import argparse
from typing import Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class MetricsCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.file: Optional[str] = namespace.file

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        metrics = parser.add_parser("metrics", help="get prometheus metrics data")
        metrics.add_argument("file", help="optional, file to export metrics to", nargs="?", default=None)
        return metrics, MetricsCommand

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/metrics"
        response = request("GET", url)

        if self.file and response.status == 200:
            with open(self.file, "w") as f:
                f.write(response.body)
        else:
            print(response)
