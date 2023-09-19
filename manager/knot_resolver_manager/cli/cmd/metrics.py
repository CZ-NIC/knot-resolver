import argparse
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class MetricsCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.file: Optional[str] = namespace.file

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        metrics = subparser.add_parser("metrics", help="get prometheus metrics data")
        metrics.add_argument(
            "file",
            help="Optional, file where to export Prometheus metrics. If not specified, the metrics are printed.",
            nargs="?",
            default=None,
        )
        return metrics, MetricsCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        response = request(args.socket, "GET", "metrics")

        if response.status == 200:
            if self.file:
                with open(self.file, "w") as f:
                    f.write(response.body)
            else:
                print(response.body)
        else:
            print(response, file=sys.stderr)
            sys.exit(1)
