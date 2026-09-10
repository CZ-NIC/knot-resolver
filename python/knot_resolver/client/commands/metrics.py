from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
    import argparse


@dataclass(frozen=True)
class MetricsCommandArgs(KresClientArgs):
    prometheus: bool
    file: Path | None


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    metrics_parser = subparser.add_parser(
        "metrics",
        help="Get aggregated metrics from the running resolver"
        " in JSON format (default) or optionally in Prometheus format."
        "\nThe 'prometheus-client' Python package needs to be installed if you wish to use the Prometheus format."
        "\nRequires a connection to the management HTTP API.",
    )
    metrics_parser.add_argument(
        "--prometheus",
        action="store_true",
        default=False,
        help="Get metrics in Prometheus format if dependencies are met in the resolver.",
    )
    metrics_parser.add_argument(
        "file",
        type=Path,
        nargs="?",
        help="Optional. The file into which metrics will be exported."
        "\nIf not specified, the metrics are printed into stdout.",
    )
    metrics_parser.set_defaults(command=MetricsCommand, command_args=MetricsCommandArgs)


class MetricsCommand(KresClientCommand):
    def __init__(self, args: MetricsCommandArgs) -> None:
        self._socket = get_socket(args)
        self._args = args

    def run(self) -> None:
        response = request(self._socket, "GET", "metrics/prometheus" if self._args.prometheus else "metrics/json")

        if response.status == 200:
            if self._args.prometheus:
                metrics = response.body
            else:
                metrics = DataFormat.JSON.dict_dump(parse_json(response.body), indent=4)

            if self._args.file:
                with self._args.file.open("w") as f:
                    f.write(metrics)
            else:
                print(metrics)
        else:
            print(response, file=sys.stderr)
            if self._args.prometheus and response.status == 404:
                print("Prometheus is unavailable due to missing optional dependencies", file=sys.stderr)
            sys.exit(1)
