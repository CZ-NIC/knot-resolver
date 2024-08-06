import argparse
import sys
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver_manager.utils.modeling.exceptions import AggregateDataValidationError, DataValidationError
from knot_resolver_manager.utils.modeling.parsing import DataFormat, parse_json
from knot_resolver_manager.utils.requests import request


class CacheOperations(Enum):
    CLEAR = 0


@register_command
class CacheCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.operation: Optional[CacheOperations] = namespace.operation if hasattr(namespace, "operation") else None
        self.out_format: DataFormat = namespace.out_format if hasattr(namespace, "out_format") else DataFormat.YAML

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
        cache_parser = subparser.add_parser("cache", help="Performs operations on the running resolver's cache.")

        config_subparsers = cache_parser.add_subparsers(help="operation type")

        # CLEAR operation
        clear_subparser = config_subparsers.add_parser("clear", help="Purge cache records matching specified criteria.")
        clear_subparser.set_defaults(operation=CacheOperations.CLEAR, exact_name=False)
        clear_subparser.add_argument(
            "--exact-name",
            help="If set, only records with the same name are removed.",
            action="store_true",
            dest="exact_name",
        )
        clear_subparser.add_argument(
            "--rr-type",
            help="Optional, you may additionally specify the type to remove, but that is only supported with '--exact-name' flag set.",
            action="store",
            type=str,
        )
        clear_subparser.add_argument(
            "--chunk-size",
            help="Optional, the number of records to remove in one round; default: 100."
            " The purpose is not to block the resolver for long. The resolver repeats the command after one millisecond until all matching data are cleared.",
            action="store",
            type=int,
            default=100,
        )
        clear_subparser.add_argument(
            "name",
            type=str,
            nargs="?",
            help="Optional, subtree to purge; if the name isn't provided, whole cache is purged (and any other parameters are disregarded).",
            default=None,
        )

        out_format = clear_subparser.add_mutually_exclusive_group()
        out_format_default = DataFormat.YAML
        out_format.add_argument(
            "--json",
            help="Set output format in JSON format, default.",
            const=DataFormat.JSON,
            action="store_const",
            dest="out_format",
            default=out_format_default,
        )
        out_format.add_argument(
            "--yaml",
            help="Set configuration data in YAML format.",
            const=DataFormat.YAML,
            action="store_const",
            dest="out_format",
            default=out_format_default,
        )

        return cache_parser, CacheCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

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
        print(self.out_format.dict_dump(body_dict, indent=4))
