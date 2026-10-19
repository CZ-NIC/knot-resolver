import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from knot_resolver.controller.interface import KresID
    from knot_resolver.datamodel.config_schema import KresConfig


LOGGING_LEVEL_STARTUP = logging.DEBUG

FIX_COUNTER_ATTEMPTS_MAX = 2
FIX_COUNTER_DECREASE_INTERVAL_SEC = 30 * 60
PROCESSES_WATCHDOG_INTERVAL_SEC: float = 5


class _UserConstants:
    """Class for accessing constants, which are technically not constants as they are user configurable."""

    def __init__(self, config: "KresConfig", working_directory_on_startup: Path) -> None:
        self._config = config
        self.working_directory_on_startup = working_directory_on_startup


_user_constants: Optional[_UserConstants] = None


async def init_user_constants(config: "KresConfig", working_directory_on_startup: Path) -> None:
    global _user_constants
    _user_constants = _UserConstants(config, working_directory_on_startup)


def user_constants() -> _UserConstants:
    assert _user_constants is not None
    return _user_constants
