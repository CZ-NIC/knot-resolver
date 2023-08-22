import argparse
import json
import sys
from typing import List, Optional, Tuple, Type, Iterable

from knot_resolver_manager.cli.command import Command, CommandArgs, CompWords, register_command
from knot_resolver_manager.utils.requests import request


PIDS_TYPE = Iterable


@register_command
class PidsCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.proc_type: Optional[str] = namespace.proc_type

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        pids = subparser.add_parser("pids", help="list the PIDs of kresd manager subprocesses")
        pids.add_argument(
            "proc_type",
            help="Optional, the type of process to query. May be 'kresd', 'gc', or 'all' (default).",
            nargs="?",
            default="all",
        )
        return pids, PidsCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        response = request(args.socket, "GET", f"pids/{self.proc_type}")

        if response.status == 200:
            pids = json.loads(response.body)
            if isinstance(pids, PIDS_TYPE):
                for pid in pids:
                    print(pid)
            else:
                print(
                    f"Unexpected response type '{type(pids).__name__}' from manager. Expected '{PIDS_TYPE.__name__}'",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            print(response, file=sys.stderr)
            sys.exit(1)
