import logging
from pathlib import Path

from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.kres_id import KresID

STARTUP_LOG_LEVEL = logging.DEBUG
DEFAULT_MANAGER_CONFIG_FILE = Path("/etc/knot-resolver/config.yml")
KRESD_EXECUTABLE = Path("/usr/sbin/kresd")
GC_EXECUTABLE = Path("/usr/sbin/kres-cache-gc")


def kresd_cache_dir(config: KresConfig) -> Path:
    return config.cache.storage.to_path()


def kresd_config_file(_config: KresConfig, kres_id: KresID) -> Path:
    return Path(f"kresd_{kres_id}.conf")


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
