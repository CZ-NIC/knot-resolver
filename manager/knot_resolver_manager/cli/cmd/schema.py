import argparse
import json
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, parser_words, register_command
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.utils.requests import request


@register_command
class SchemaCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.live: bool = namespace.live
        self.file: Optional[str] = namespace.file

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        schema = subparser.add_parser(
            "schema", help="Shows JSON-schema repersentation of the Knot Resolver's configuration."
        )
        schema.add_argument(
            "-l",
            "--live",
            help="Get current configuration JSON-schema directly from the running resolver. Requires connection to the management API.",
            action="store_true",
            default=False,
        )
        schema.add_argument("file", help="Optional, file where to export JSON-schema.", nargs="?", default=None)

        return schema, SchemaCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return parser_words(parser._actions)  # pylint: disable=W0212

    def run(self, args: CommandArgs) -> None:
        if self.live:
            response = request("GET", f"{args.socket}/schema")
            if response.status == 200:
                schema = response.body
            else:
                print(response)
                sys.exit(1)
        else:
            schema = json.dumps(KresConfig.json_schema(), indent=4)

        if self.file:
            with open(self.file, "w") as f:
                f.write(schema)
        else:
            print(schema)
