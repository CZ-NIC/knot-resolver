import argparse
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, register_command
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver.utils.requests import request


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
            help="Get aggregated metrics from the running resolver in JSON format (default) or optionally in Prometheus format."
            "\nThe 'prometheus-client' Python package needs to be installed if you wish to use the Prometheus format."
            "\nRequires a connection to the management HTTP API.",
        )

        metrics.add_argument(
            "--prometheus",
            help="Get metrics in Prometheus format if dependencies are met in the resolver.",
            action="store_true",
            default=False,
        )

        metrics.add_argument(
            "file",
            help="Optional. The file into which metrics will be exported."
            "\nIf not specified, the metrics are printed into stdout.",
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
            if self.prometheus and response.status == 404:
                print("Prometheus is unavailable due to missing optional dependencies", file=sys.stderr)
            sys.exit(1)
