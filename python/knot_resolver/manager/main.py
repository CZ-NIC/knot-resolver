from __future__ import annotations

import asyncio
import sys

from knot_resolver.args import parse_args
from knot_resolver.logging import start_logging

from .manager import start_manager


def main() -> None:
    args = parse_args()
    start_logging("manager", args)
    exit_code = asyncio.run(start_manager(args))
    sys.exit(exit_code)
