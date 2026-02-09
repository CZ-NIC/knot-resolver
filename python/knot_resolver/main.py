from __future__ import annotations

from .args import parse_args
from .logging import start_logging
from .resolver import start_resolver


def main() -> None:
    args = parse_args()
    start_logging("knot-resolver", args)
    start_resolver(args)
