import importlib.util
from pathlib import Path

VERSION = "6.0.11"
USER = "knot-resolver"
GROUP = "knot-resolver"

# default files names
API_SOCK_NAME = "kres-api.sock"

# default dirs paths
RUN_DIR = Path("/run/knot-resolver")
ETC_DIR = Path("/etc/knot-resolver")
SBIN_DIR = Path("/usr/sbin")
CACHE_DIR = Path("/var/cache/knot-resolver")

# default files paths
CONFIG_FILE = ETC_DIR / "config.yaml"
API_SOCK_FILE = RUN_DIR / API_SOCK_NAME

# executables paths
KRESD_EXECUTABLE = SBIN_DIR / "kresd"
KRES_CACHE_GC_EXECUTABLE = SBIN_DIR / "kres-cache-gc"

WATCHDOG_LIB = False
if importlib.util.find_spec("watchdog"):
    WATCHDOG_LIB = True

PROMETHEUS_LIB = False
if importlib.util.find_spec("prometheus_client"):
    PROMETHEUS_LIB = True
