from __future__ import annotations

import asyncio
import sys

from knot_resolver.args import parse_args

from .logger import logger_startup
from .server import start_server


def main() -> None:
    args = parse_args()
    logger_startup()
    exit_code = asyncio.run(start_server(args))
    sys.exit(exit_code)
