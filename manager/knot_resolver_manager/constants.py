import importlib.util
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional

# Install config is semi-optional - only needed to actually run Manager, but not
# for its unit tests.
if importlib.util.find_spec("knot_resolver"):
    import knot_resolver  # type: ignore[import-not-found]
else:
    knot_resolver = None

if TYPE_CHECKING:
    from knot_resolver_manager.config_store import ConfigStore
    from knot_resolver_manager.datamodel.config_schema import KresConfig
    from knot_resolver_manager.kresd_controller.interface import KresID

STARTUP_LOG_LEVEL = logging.DEBUG
DEFAULT_MANAGER_CONFIG_FILE = Path("/etc/knot-resolver/config.yaml")
CONFIG_FILE_ENV_VAR = "KRES_MANAGER_CONFIG"
API_SOCK_ENV_VAR = "KRES_MANAGER_API_SOCK"
MANAGER_FIX_ATTEMPT_MAX_COUNTER = 2
FIX_COUNTER_DECREASE_INTERVAL_SEC = 30 * 60
PID_FILE_NAME = "manager.pid"
MAX_WORKERS = 256


def kresd_executable() -> Path:
    assert knot_resolver is not None
    return knot_resolver.sbin_dir / "kresd"


def kres_gc_executable() -> Path:
    assert knot_resolver is not None
    return knot_resolver.sbin_dir / "kres-cache-gc"


def kresd_user():
    return None if knot_resolver is None else knot_resolver.user


def kresd_group():
    return None if knot_resolver is None else knot_resolver.group


def kresd_cache_dir(config: "KresConfig") -> Path:
    return config.cache.storage.to_path()


def policy_loader_config_file(_config: "KresConfig") -> Path:
    return Path("policy-loader.conf")


def kresd_config_file(_config: "KresConfig", kres_id: "KresID") -> Path:
    return Path(f"kresd{int(kres_id)}.conf")


def kresd_config_file_supervisord_pattern(_config: "KresConfig") -> Path:
    return Path("kresd%(process_num)d.conf")


def supervisord_config_file(_config: "KresConfig") -> Path:
    return Path("supervisord.conf")


def supervisord_config_file_tmp(_config: "KresConfig") -> Path:
    return Path("supervisord.conf.tmp")


def supervisord_pid_file(_config: "KresConfig") -> Path:
    return Path("supervisord.pid")


def supervisord_sock_file(_config: "KresConfig") -> Path:
    return Path("supervisord.sock")


def supervisord_subprocess_log_dir(_config: "KresConfig") -> Path:
    return Path("logs")


WATCHDOG_INTERVAL: float = 5
"""
Used in KresdManager. It's a number of seconds in between system health checks.
"""


class _UserConstants:
    """
    Class for accessing constants, which are technically not constants as they are user configurable.
    """

    def __init__(self, config_store: "ConfigStore", working_directory_on_startup: str) -> None:
        self._config_store = config_store
        self.working_directory_on_startup = working_directory_on_startup


_user_constants: Optional[_UserConstants] = None


async def init_user_constants(config_store: "ConfigStore", working_directory_on_startup: str) -> None:
    global _user_constants
    _user_constants = _UserConstants(config_store, working_directory_on_startup)


def user_constants() -> _UserConstants:
    assert _user_constants is not None
    return _user_constants
