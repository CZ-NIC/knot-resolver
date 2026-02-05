import logging

import knot_resolver.logging as kres_logging


def test_logger_notice() -> None:
    logger = logging.getLogger(__name__)
    logger.notice("this is NOTICE message")
