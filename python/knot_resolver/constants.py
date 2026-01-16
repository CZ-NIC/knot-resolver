import importlib.util
import platform
import re
from pathlib import Path

VERSION = "6.1.0"
USER = "knot-resolver"
GROUP = "knot-resolver"

# dirs paths
RUN_DIR = Path("/run/knot-resolver")
ETC_DIR = Path("/etc/knot-resolver")
SBIN_DIR = Path("/usr/sbin")
CACHE_DIR = Path("/var/cache/knot-resolver")
WORK_DIR = Path("/var/lib/knot-resolver")

# files paths
CONFIG_FILE = ETC_DIR / "config.yaml"
API_SOCK_FILE = RUN_DIR / "kres-api.sock"

# executables paths
KRESD_EXECUTABLE = SBIN_DIR / "kresd"
KRES_CACHE_GC_EXECUTABLE = SBIN_DIR / "kres-cache-gc"

LINUX_SYS = platform.system() == "Linux"
FREEBSD_SYS = platform.system() == "FreeBSD"

WATCHDOG_LIB = bool(importlib.util.find_spec("watchdog"))
PROMETHEUS_LIB = bool(importlib.util.find_spec("prometheus_client"))
KAFKA_LIB = bool(importlib.util.find_spec("kafka"))


def _freebsd_workers_support() -> bool:
    if FREEBSD_SYS:
        release = platform.release()
        match = re.match(r"(\d+)", release)
        if match:
            freebsd_min_version = 12
            return int(match.group(1)) >= freebsd_min_version
    return False


# It is possible to configure multiple kresd workers on Linux systems due to the SO_REUSEPORT socket option.
# FreeBSD version >=12 supports it specifically due to the additional SO_REUSEPORT_LB socket option.
WORKERS_SUPPORT = LINUX_SYS or _freebsd_workers_support()

# Systemd-like NOTIFY message is supported only on Linux systems
NOTIFY_SUPPORT = LINUX_SYS
