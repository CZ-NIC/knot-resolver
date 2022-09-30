import argparse
import json
from typing import Dict, List, Optional, Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.datamodel.config_schema import KresConfig


@register_command
class SchemaCommand(Command):
    def __init__(self, namespace: argparse.Namespace, unknown_args: List[str]) -> None:
        self.file: Optional[str] = namespace.file

        super().__init__(namespace, unknown_args)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        schema = subparser.add_parser("schema", help="get JSON schema representation of the configuration")
        schema.add_argument("file", help="optional, file to export JSON schema to", nargs="?", default=None)
        return schema, SchemaCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> Dict[str, Optional[str]]:
        return {}

    def run(self, args: CommandArgs) -> None:
        schema = json.dumps(KresConfig.json_schema(), indent=4)

        if self.file:
            with open(self.file, "w") as f:
                f.write(schema)
        else:
            print(schema)
