from pathlib import Path

VERSION = "6.0.9"
USER = "knot-resolver"
GROUP = "knot-resolver"

# dirs paths
RUN_DIR = Path("/run/knot-resolver")
ETC_DIR = Path("/etc/knot-resolver")
SBIN_DIR = Path("/usr/sbin")
CACHE_DIR = Path("/var/cache/knot-resolver")

# files paths
CONFIG_FILE = ETC_DIR / "config.yaml"
API_SOCK_FILE = RUN_DIR / "kres-api.sock"

# executables paths
KRESD_EXECUTABLE = SBIN_DIR / "kresd"
KRES_CACHE_GC_EXECUTABLE = SBIN_DIR / "kres-cache-gc"
