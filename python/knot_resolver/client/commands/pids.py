import argparse
import json
import sys
from typing import Iterable, List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, register_command
from knot_resolver.utils.requests import request

PROCESSES_TYPE = Iterable


@register_command
class PidsCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.proc_type: Optional[str] = namespace.proc_type
        self.json: int = namespace.json

        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        pids = subparser.add_parser("pids", help="List the PIDs of the Manager's subprocesses")
        pids.add_argument(
            "proc_type",
            help="Optional, the type of process to query. May be 'kresd', 'gc', or 'all' (default).",
            nargs="?",
            default="all",
        )
        pids.add_argument(
            "--json",
            help="Optional, makes the output more verbose, in JSON.",
            action="store_true",
            default=False,
        )
        return pids, PidsCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:
        response = request(args.socket, "GET", f"processes/{self.proc_type}")

        if response.status == 200:
            processes = json.loads(response.body)
            if isinstance(processes, PROCESSES_TYPE):
                if self.json:
                    print(json.dumps(processes, indent=2))
                else:
                    for p in processes:
                        print(p["pid"])

            else:
                print(
                    f"Unexpected response type '{type(processes).__name__}' from manager. Expected '{PROCESSES_TYPE.__name__}'",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            print(response, file=sys.stderr)
            sys.exit(1)
