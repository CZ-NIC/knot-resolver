from pathlib import Path

VERSION = "6.0.8"
USER = "ftobias"
GROUP = "ftobias"

# dirs paths
RUN_DIR = Path("/home/ftobias/knot_projects/knot-resolver/.install_dev/run/knot-resolver")
ETC_DIR = Path("/home/ftobias/knot_projects/knot-resolver/.install_dev/etc/knot-resolver")
SBIN_DIR = Path("/home/ftobias/knot_projects/knot-resolver/.install_dev/sbin")
CACHE_DIR = Path("/home/ftobias/knot_projects/knot-resolver/.install_dev/var/cache/knot-resolver")

# files paths
CONFIG_FILE = ETC_DIR / "config.yaml"
API_SOCK_FILE = RUN_DIR / "kres-api.sock"

# executables paths
KRESD_EXECUTABLE = SBIN_DIR / "kresd"
KRES_CACHE_GC_EXECUTABLE = SBIN_DIR / "kres-cache-gc"
