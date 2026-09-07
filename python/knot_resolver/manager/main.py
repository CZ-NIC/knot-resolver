from __future__ import annotations

import asyncio
import sys

from knot_resolver.args import parse_args
from knot_resolver.logging import start_logging

from .server import start_server

MANAGER_DESCRIPTION = (
    "Knot Resolver Manager - A Python program for "
    "managing and orchestrating Knot Resolver components."
)


def main() -> None:
    args = parse_args(description=MANAGER_DESCRIPTION)
    start_logging(args, "manager")
    exit_code = asyncio.run(start_server(args))
    sys.exit(exit_code)
