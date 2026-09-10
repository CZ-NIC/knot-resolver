from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.datamodel import kres_config_json_schema
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
    import argparse


@dataclass(frozen=True)
class SchemaCommandArgs(KresClientArgs):
    live: bool
    file: Path | None


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    schema_parser = subparser.add_parser(
        "schema", help="Shows JSON-schema repersentation of the Knot Resolver's configuration."
    )
    schema_parser.add_argument(
        "-l",
        "--live",
        action="store_true",
        default=False,
        help="Get configuration JSON-schema from the running resolver. Requires connection to the management API.",
    )
    schema_parser.add_argument(
        "file",
        type=Path,
        nargs="?",
        help="Optional, file where to export JSON-schema.",
    )
    schema_parser.set_defaults(command=SchemaCommand, command_args=SchemaCommandArgs)


class SchemaCommand(KresClientCommand):
    def __init__(self, args: SchemaCommandArgs) -> None:
        self._args = args

    def run(self) -> None:
        if self._args.live:
            sock = get_socket(self._args)
            response = request(sock, "GET", "schema")
            if response.status != 200:
                print(response, file=sys.stderr)
                sys.exit(1)
            schema = response.body
        else:
            schema = json.dumps(kres_config_json_schema(), indent=4)

        if self._args.file:
            with self._args.file.open("w") as f:
                f.write(schema)
        else:
            print(schema)
