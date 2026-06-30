from knot_resolver.logging import get_logger


def test_logger_notice() -> None:
    logger = get_logger(__name__)
    logger.notice("this is NOTICE message")
