from __future__ import annotations

import asyncio
import sys

from .args import parse_args
from .launcher import start_resolver
from .logging import start_logging


def main() -> None:
    args = parse_args()
    start_logging(args, "launcher")
    exit_code = asyncio.run(start_resolver(args))
    sys.exit(exit_code)
