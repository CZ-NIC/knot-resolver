import logging
from importlib.metadata import version
from importlib.util import find_spec
from pathlib import Path

# Installed Knot Resolver build options from Meson is semi-optional.
# They are needed to run the resolver, but not for its unit tests.
if find_spec("knot_resolver_build_options"):
    import knot_resolver_build_options as build_conf  # type: ignore[import-not-found]
else:
    build_conf = None

VERSION = version("knot_resolver") if find_spec("knot_resolver") else "6"
WORKERS_MAX_DEFAULT = 256
LOGGING_LEVEL_STARTUP = logging.DEBUG
PID_FILE_NAME = "knot-resolver.pid"

FIX_COUNTER_ATTEMPTS_MAX = 2
FIX_COUNTER_DECREASE_INTERVAL_SEC = 30 * 60
WATCHDOG_INTERVAL_SEC: float = 5

USER_DEFAULT = build_conf.user if build_conf else "knot-resolver"
GROUP_DEFAULT = build_conf.group if build_conf else "knot-resolver"

RUN_DIR_DEFAULT: Path = build_conf.run_dir if build_conf else Path("/var/run/knot-resolver")
ETC_DIR_DEFAULT: Path = build_conf.etc_dir if build_conf else Path("/etc/knot-resolver")
CONFIG_FILE_PATH_DEFAULT = ETC_DIR_DEFAULT / "config.yaml"
CONFIG_FILE_PATH_ENV_VAR = "KRES_MANAGER_CONFIG"
API_SOCK_PATH_DEFAULT = RUN_DIR_DEFAULT / "kres-api.sock"
API_SOCK_PATH_ENV_VAR = "KRES_MANAGER_API_SOCK"


def kresd_executable() -> Path:
    assert build_conf is not None
    return build_conf.sbin_dir / "kresd"


def kres_cache_gc_executable() -> Path:
    assert build_conf is not None
    return build_conf.sbin_dir / "kres-cache-gc"
