from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


def start_manager(config: list[str]) -> int:
    start_time = time()
    logger.info("Starting the Manager...")






    run_time = time() - start_time
    logger.info("The Manager ran for %d seconds...", round(run_time))
    return 0
