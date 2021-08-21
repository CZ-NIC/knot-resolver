import logging
from pathlib import Path

LOG_LEVEL = logging.DEBUG

CONFIGURATION_DIR = Path("etc/knot-resolver").absolute()
CONFIGURATION_DIR.mkdir(exist_ok=True)
RUNTIME_DIR = Path("etc/knot-resolver/runtime").absolute()
RUNTIME_DIR.mkdir(exist_ok=True)
KRES_CACHE_DIR = Path("etc/knot-resolver/cache").absolute()
KRES_CACHE_DIR.mkdir(exist_ok=True)


KRESD_EXECUTABLE = Path("/usr/sbin/kresd")
GC_EXECUTABLE = Path("/usr/sbin/kres-cache-gc")
# KRES_CACHE_DIR = Path("/var/lib/knot-resolver")

KRESD_CONFIG_FILE = RUNTIME_DIR / "kresd.conf"
KRESD_SUPERVISORD_ARGS = f"-c {str(KRESD_CONFIG_FILE.absolute())} -n -vvv"
KRES_GC_SUPERVISORD_ARGS = f"-c {KRES_CACHE_DIR.absolute()} -d 1000"

SUPERVISORD_CONFIG_FILE = RUNTIME_DIR / "supervisord.conf"
SUPERVISORD_CONFIG_FILE_TMP = RUNTIME_DIR / "supervisord.conf.tmp"
SUPERVISORD_PID_FILE = RUNTIME_DIR / "supervisord.pid"
SUPERVISORD_SOCK = RUNTIME_DIR / "supervisord.sock"
SUPERVISORD_LOGFILE = RUNTIME_DIR / "supervisord.log"

SUPERVISORD_SUBPROCESS_LOG_DIR = RUNTIME_DIR / "logs"
SUPERVISORD_SUBPROCESS_LOG_DIR.mkdir(exist_ok=True)

MANAGER_CONFIG_FILE = CONFIGURATION_DIR / "config.yml"

LISTEN_SOCKET_PATH = RUNTIME_DIR / "manager.sock"

"""
Used in KresdManager. It's a number of seconds in between system health checks.
"""
WATCHDOG_INTERVAL: float = 5
