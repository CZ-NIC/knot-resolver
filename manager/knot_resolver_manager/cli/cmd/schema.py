import argparse
from optparse import Option
import sys
from typing import Optional, Tuple, Type
from knot_resolver_manager.utils.requests import request

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command


@register_command
class SchemaCommand(Command):

    def __init__(self, namespace: argparse.Namespace) -> None:
        self.file: Optional[str] = namespace.file

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        schema = parser.add_parser("schema", help="get JSON schema reprezentation of the configuration")
        schema.add_argument('file', help="optional, file to export JSON schema to", nargs='?', default=None)
        return schema, SchemaCommand

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/schema"
        response = request("GET", url)

        if self.file and response.status == 200:
            with open(self.file, 'w') as f:
                f.write(response.body)
        else:
            print(response)
