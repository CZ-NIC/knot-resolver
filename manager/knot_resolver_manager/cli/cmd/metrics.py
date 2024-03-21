import argparse
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver_manager.utils.requests import request


@register_command
class MetricsCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.file: Optional[str] = namespace.file
        self.prometheus: bool = namespace.prometheus

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        metrics = subparser.add_parser(
            "metrics",
            help="Get metrics from the running resolver in JSON format by default or optionally in Prometheus format.",
        )

        metrics.add_argument(
            "--prometheus",
            help="Get metrics in Prometheus format if supported in the resolver.",
            action="store_true",
            default=False,
        )

        metrics.add_argument(
            "file",
            help="Optional, file where to export metrics. If not specified, the metrics are printed.",
            nargs="?",
            default=None,
        )
        return metrics, MetricsCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        response = request(args.socket, "GET", "metrics/prometheus" if self.prometheus else "metrics/json")

        if response.status == 200:
            if self.prometheus:
                metrics = response.body
            else:
                metrics = DataFormat.JSON.dict_dump(parse_json(response.body), indent=4)

            if self.file:
                with open(self.file, "w") as f:
                    f.write(metrics)
            else:
                print(metrics)
        else:
            print(response, file=sys.stderr)
            sys.exit(1)
