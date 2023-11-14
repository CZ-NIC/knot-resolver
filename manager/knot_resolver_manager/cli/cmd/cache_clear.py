import argparse
import sys
from typing import Any, Dict, List, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver_manager.utils.modeling.exceptions import AggregateDataValidationError, DataValidationError
from knot_resolver_manager.utils.modeling.parsing import DataFormat
from knot_resolver_manager.utils.requests import request


@register_command
class CacheClearCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

        config_dict: Dict[str, Any] = {"exact-name": namespace.exact_name}

        if hasattr(namespace, "name"):
            config_dict["name"] = namespace.name
        if hasattr(namespace, "rr_type"):
            config_dict["rr-type"] = namespace.rr_type
        if hasattr(namespace, "chunk_size"):
            config_dict["chunk-size"] = namespace.chunk_size

        try:
            self.config = CacheClearRPCSchema(config_dict)
        except (AggregateDataValidationError, DataValidationError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        cache_clear = subparser.add_parser("cache-clear", help="Purge cache records matching specified criteria.")
        cache_clear.set_defaults(exact_name=False)
        cache_clear.add_argument(
            "--exact-name",
            help="If set, only records with the same name are removed.",
            action="store_true",
            dest="exact_name",
        )
        cache_clear.add_argument(
            "--rr-type",
            help="Optional, you may additionally specify the type to remove, but that is only supported with '--exact-name' flag set.",
            action="store",
            type=str,
        )
        cache_clear.add_argument(
            "--chunk-size",
            help="Optional, the number of records to remove in one round; default: 100."
            " The purpose is not to block the resolver for long. The resolver repeats the command after one millisecond until all matching data are cleared.",
            action="store",
            type=int,
            default=100,
        )
        cache_clear.add_argument(
            "name",
            type=str,
            nargs="?",
            help="Optional, subtree to purge; if the name isn't provided, whole cache is purged (and any other parameters are disregarded).",
            default=None,
        )

        return cache_clear, CacheClearCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        body: str = DataFormat.JSON.dict_dump(self.config.get_unparsed_data())
        response = request(args.socket, "POST", "cache-clear", body)

        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)
        print(response.body)
