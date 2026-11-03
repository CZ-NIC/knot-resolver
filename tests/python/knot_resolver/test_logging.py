import logging
from unittest.mock import patch

import pytest

from knot_resolver.logging import LOGGING_NOTICE, KresLogger, _config_to_level, _level_to_name, get_logger


class TestLoggingLevels:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            ("crit", logging.CRITICAL),
            ("err", logging.ERROR),
            ("warning", logging.WARNING),
            ("notice", LOGGING_NOTICE),
            ("info", logging.INFO),
            ("debug", logging.DEBUG),
        ],
    )
    def test_config_to_level(self, level, expected):
        assert _config_to_level[level] == expected

    @pytest.mark.parametrize(
        ("level", "expected"),
        [
            (logging.CRITICAL, "CRIT"),
            (logging.ERROR, "ERRO"),
            (logging.WARNING, "WARN"),
            (LOGGING_NOTICE, "NOTI"),
            (logging.INFO, "INFO"),
            (logging.DEBUG, "DEBG"),
        ],
    )
    def test_level_to_name(self, level, expected):
        assert _level_to_name[level] == expected
        assert logging._levelToName[level] == expected

    def test_notice_value(self):
        assert LOGGING_NOTICE == (logging.WARNING + logging.INFO) // 2


class TestKresLogger:
    def test_get_logger(self):
        logger = get_logger("test_named_logger")

        assert isinstance(logger, KresLogger)
        assert logger.name == "test_named_logger"

    def test_notice_logs_enabled(self):
        logger = get_logger("test_notice_enabled")
        logger.setLevel(LOGGING_NOTICE)

        with patch.object(logger, "_log") as mock_log:
            logger.notice("test message")

        mock_log.assert_called_once_with(
            LOGGING_NOTICE,
            "test message",
            (),
        )

    def test_notice_logs_disabled(self):
        logger = get_logger("test_notice_disabled")
        logger.setLevel(logging.WARNING)

        with patch.object(logger, "_log") as mock_log:
            logger.notice("test message")

        mock_log.assert_not_called()
