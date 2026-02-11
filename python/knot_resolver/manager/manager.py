from __future__ import annotations

from typing import TYPE_CHECKING

from knot_resolver.logging import get_logger

if TYPE_CHECKING:
    from knot_resolver.args import KresArgs

logger = get_logger(__name__)


async def start_manager(args: KresArgs) -> int:
    logger.notice("Starting Knot Resolver Manager...")
    return 0
