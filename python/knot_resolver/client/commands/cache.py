# noqa: INP001
import argparse
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, comp_get_words, register_command
from knot_resolver.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver.utils.modeling.exceptions import AggregateDataValidationError, DataValidationError
from knot_resolver.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver.utils.requests import request


class CacheOperations(Enum):
    CLEAR = 0


@register_command
class CacheCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.operation: Optional[CacheOperations] = namespace.operation if hasattr(namespace, "operation") else None
        self.output_format: DataFormat = (
            namespace.output_format if hasattr(namespace, "output_format") else DataFormat.YAML
        )

        # CLEAR operation
        self.clear_dict: Dict[str, Any] = {}
        if hasattr(namespace, "exact_name"):
            self.clear_dict["exact-name"] = namespace.exact_name
        if hasattr(namespace, "name"):
            self.clear_dict["name"] = namespace.name
        if hasattr(namespace, "rr_type"):
            self.clear_dict["rr-type"] = namespace.rr_type
        if hasattr(namespace, "chunk_size"):
            self.clear_dict["chunk-size"] = namespace.chunk_size

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        cache_parser = subparser.add_parser("cache", help="Performs operations on the cache of the running resolver.")

        config_subparsers = cache_parser.add_subparsers(help="operation type")

        # 'clear' operation
        clear_subparser = config_subparsers.add_parser(
            "clear", help="Purge cache records that match specified criteria."
        )
        clear_subparser.set_defaults(operation=CacheOperations.CLEAR, exact_name=False)
        clear_subparser.add_argument(
            "--exact-name",
            help="If set, only records with the same name are purged.",
            action="store_true",
            dest="exact_name",
        )
        clear_subparser.add_argument(
            "--rr-type",
            help="Optional, the resource record type to purge. It is supported only with the '--exact-name' flag set.",
            action="store",
            type=str,
        )
        clear_subparser.add_argument(
            "--chunk-size",
            help="Optional, the number of records to remove in one round; the default is 100."
            " The purpose is not to block the resolver for long."
            " The resolver repeats the cache clearing after one millisecond until all matching data is cleared.",
            action="store",
            type=int,
            default=100,
        )
        clear_subparser.add_argument(
            "name",
            type=str,
            nargs="?",
            help="Optional, subtree name to purge; if omitted, the entire cache is purged (and all other parameters are ignored).",
            default=None,
        )

        output_format = clear_subparser.add_mutually_exclusive_group()
        output_format_default = DataFormat.YAML
        output_format.add_argument(
            "--json",
            help="Set JSON as the output format.",
            const=DataFormat.JSON,
            action="store_const",
            dest="output_format",
            default=output_format_default,
        )
        output_format.add_argument(
            "--yaml",
            help="Set YAML as the output format. YAML is the default.",
            const=DataFormat.YAML,
            action="store_const",
            dest="output_format",
            default=output_format_default,
        )

        return cache_parser, CacheCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return comp_get_words(args, parser)

    def run(self, args: CommandArgs) -> None:
        if not self.operation:
            args.subparser.print_help()
            sys.exit()

        if self.operation == CacheOperations.CLEAR:
            try:
                validated = CacheClearRPCSchema(self.clear_dict)
            except (AggregateDataValidationError, DataValidationError) as e:
                print(e, file=sys.stderr)
                sys.exit(1)

            body: str = DataFormat.JSON.dict_dump(validated.get_unparsed_data())
            response = request(args.socket, "POST", "cache/clear", body)
            body_dict = parse_json(response.body)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)
        print(self.output_format.dict_dump(body_dict, indent=4))
