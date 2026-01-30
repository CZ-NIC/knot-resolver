from __future__ import annotations

import logging
from time import time

from .controller.supervisord import SupervisordSubprocessController

logger = logging.getLogger(__name__)


async def start_resolver(config: list[str]) -> int:
    start_time = time()
    logger.notice("Starting Knot Resolver...")

    controller = SupervisordSubprocessController()


    run_time = time() - start_time
    logger.notice("Knot Resolver ran for %d seconds...", round(run_time))
    return 0
