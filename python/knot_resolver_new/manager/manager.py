from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def start_manager(config: list[str]) -> int:
    start_time = time()






    run_time = round(time() - start_time)

    logger.info(f"The manager run for {round(time() - start_time)} seconds...")
