from __future__ import annotations

import asyncio
import sys

from .args import parse_args
from .logging import start_logging
from .resolver import start_resolver


def main() -> None:
    args = parse_args()
    start_logging(args)
    exit_code = asyncio.run(start_resolver(args))
    sys.exit(exit_code)
