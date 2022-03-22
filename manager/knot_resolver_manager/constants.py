import logging
from pathlib import Path
from typing import TYPE_CHECKING

from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.utils import which

if TYPE_CHECKING:
    from knot_resolver_manager.kresd_controller.interface import KresID

STARTUP_LOG_LEVEL = logging.DEBUG
DEFAULT_MANAGER_CONFIG_FILE = Path("/etc/knot-resolver/config.yml")
MANAGER_FIX_ATTEMPT_MAX_COUNTER = 2
FIX_COUNTER_DECREASE_INTERVAL_SEC = 30 * 60
PID_FILE_NAME = "manager.pid"


def kresd_executable() -> Path:
    return which.which("kresd")


def kres_gc_executable() -> Path:
    return which.which("kres-cache-gc")


def kresd_cache_dir(config: KresConfig) -> Path:
    return config.cache.storage.to_path()


def kresd_config_file(_config: KresConfig, kres_id: "KresID") -> Path:
    return Path(f"{kres_id}.conf")


def supervisord_config_file(_config: KresConfig) -> Path:
    return Path("supervisord.conf")


def supervisord_config_file_tmp(_config: KresConfig) -> Path:
    return Path("supervisord.conf.tmp")


def supervisord_log_file(_config: KresConfig) -> Path:
    return Path("supervisord.log")


def supervisord_pid_file(_config: KresConfig) -> Path:
    return Path("supervisord.pid")


def supervisord_sock_file(_config: KresConfig) -> Path:
    return Path("supervisord.sock")


def supervisord_subprocess_log_dir(_config: KresConfig) -> Path:
    return Path("logs")


WATCHDOG_INTERVAL: float = 5
"""
Used in KresdManager. It's a number of seconds in between system health checks.
"""
