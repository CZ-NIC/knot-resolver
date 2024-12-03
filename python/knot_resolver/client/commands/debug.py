import argparse
import json
import os
import sys
from typing import List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, register_command
from knot_resolver.utils import which
from knot_resolver.utils.requests import request

PIDS_TYPE = List


@register_command
class DebugCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        self.proc_type: Optional[str] = namespace.proc_type
        self.sudo: bool = namespace.sudo
        self.gdb: str = namespace.gdb
        self.gdb_args: List[str] = namespace.extra
        super().__init__(namespace)

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        debug = subparser.add_parser(
            "debug",
            help="Run GDB on the manager's subprocesses - runs with sudo by default to avoid ptrace_scope issues",
        )
        debug.add_argument(
            "proc_type",
            help="Optional, the type of process to debug. May be 'kresd' (default), 'gc', or 'all'.",
            type=str,
            nargs="?",
            default="kresd",
        )
        debug.add_argument(
            "--no-sudo",
            dest="sudo",
            help="Do not run GDB with sudo (may not work if your ptrace_scope is 1 or higher)",
            action="store_false",
        )
        debug.add_argument(
            "--gdb",
            help="GDB command (may be a command on PATH, or an absolute path)",
            type=str,
            default="gdb",
        )
        return debug, DebugCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return {}

    def run(self, args: CommandArgs) -> None:  # noqa: PLR0912, PLR0915
        gdb_cmd = str(which.which(self.gdb))
        sudo_cmd = str(which.which("sudo"))

        response = request(args.socket, "GET", f"pids/{self.proc_type}")
        if response.status != 200:
            print(response, file=sys.stderr)
            sys.exit(1)

        pids = json.loads(response.body)
        if not isinstance(pids, PIDS_TYPE):
            print(
                f"Unexpected response type '{type(pids).__name__}' from manager. Expected '{PIDS_TYPE.__name__}'",
                file=sys.stderr,
            )
            sys.exit(1)
        if len(pids) == 0:
            print(
                f"There are no processes of type '{self.proc_type}' available to debug",
                file=sys.stderr,
            )

        exec_args = []

        if self.sudo:
            exec_args.extend([sudo_cmd, "--"])

        # attach to PIDs
        exec_args.extend([gdb_cmd, "--pid", str(pids[0])])
        inferior = 2
        for pid in pids[1:]:
            exec_args.extend(["-init-eval-command", "add-inferior"])
            exec_args.extend(["-init-eval-command", f"inferior {inferior}"])
            exec_args.extend(["-init-eval-command", f"attach {pid}"])
            inferior += 1

        exec_args.extend(["-init-eval-command", "inferior 1"])
        exec_args.extend(self.gdb_args)

        print(f"exec_args = {exec_args}")
        os.execl(*exec_args)
