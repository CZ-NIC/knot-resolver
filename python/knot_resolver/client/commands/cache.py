from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from knot_resolver.client.args import KresClientArgs
from knot_resolver.client.command import KresClientCommand, get_socket
from knot_resolver.client.completion import CompletionWords, comp_get_words
from knot_resolver.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver.utils.modeling.exceptions import AggregateDataValidationError, DataValidationError
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver.utils.requests import request

if TYPE_CHECKING:
    import argparse


@dataclass(frozen=True)
class CacheCommandArgs(KresClientArgs):
    operation: CacheOperation
    exact_name: bool
    rr_type: str | None
    chunk_size: int
    name: str | None
    output_format: DataFormat


class CacheOperation(int, Enum):
    CLEAR = 0


def register_subparser(subparser: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    cache_parser = subparser.add_parser("cache", help="Performs operations on the cache of the running resolver.")
    cache_subparsers = cache_parser.add_subparsers(dest="operation", help="operation type", required=True)

    clear_subparser = cache_subparsers.add_parser("clear", help="Purge cache records that match specified criteria.")
    clear_subparser.set_defaults(operation=CacheOperation.CLEAR)
    clear_subparser.add_argument(
        "--exact-name",
        action="store_true",
        default=False,
        help="If set, only records with the same name are purged.",
    )
    clear_subparser.add_argument(
        "--rr-type",
        action="store",
        help="Optional, the resource record type to purge. It is supported only with the '--exact-name' flag set.",
    )
    clear_subparser.add_argument(
        "--chunk-size",
        type=int,
        default=100,
        action="store",
        help="The number of records to remove in one round; the default is 100."
        " The purpose is not to block the resolver for long."
        " The resolver repeats the cache clearing after one millisecond until all matching data is cleared.",
    )
    clear_subparser.add_argument(
        "name",
        nargs="?",
        help="Optional, subtree name to purge; if omitted,"
        " the entire cache is purged (and all other parameters are ignored).",
    )

    output_format = clear_subparser.add_mutually_exclusive_group()
    output_format.add_argument(
        "--json",
        const=DataFormat.JSON,
        action="store_const",
        dest="output_format",
        default=DataFormat.YAML,
        help="Set JSON as the output format.",
    )
    output_format.add_argument(
        "--yaml",
        const=DataFormat.YAML,
        action="store_const",
        dest="output_format",
        help="Set YAML as the output format. YAML is the default.",
    )
    cache_parser.set_defaults(command=CacheCommand, command_args=CacheCommandArgs)


class CacheCommand(KresClientCommand):
    def __init__(self, args: CacheCommandArgs) -> None:
        self._socket = get_socket(args)
        self._args = args

    def run(self) -> None:
        if self._args.operation == CacheOperation.CLEAR:
            clear_dict: dict[str, str | int | bool] = {}
            if self._args.exact_name:
                clear_dict["exact-name"] = self._args.exact_name
            if self._args.name:
                clear_dict["name"] = self._args.name
            if self._args.rr_type:
                clear_dict["rr-type"] = self._args.rr_type
            if self._args.chunk_size:
                clear_dict["chunk-size"] = self._args.chunk_size

            try:
                validated = CacheClearRPCSchema(clear_dict)
            except (AggregateDataValidationError, DataValidationError) as e:
                print(e, file=sys.stderr)
                sys.exit(1)

            body: str = DataFormat.JSON.dict_dump(validated.get_unparsed_data())
            response = request(self._socket, "POST", "cache/clear", body)
            body_dict = parse_json(response.body)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)
        print(self._args.output_format.dict_dump(body_dict, indent=4))

    @staticmethod
    def completion(args: list[str], parser: argparse.ArgumentParser) -> CompletionWords:
        return comp_get_words(args, parser)
