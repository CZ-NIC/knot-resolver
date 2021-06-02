from pathlib import Path

CONFIGURATION_DIR = Path("/etc/knot-resolver")

KRESD_CONFIG_FILE = CONFIGURATION_DIR / "kresd.conf"
MANAGER_CONFIG_FILE = CONFIGURATION_DIR / "config.yml"

LISTEN_SOCKET_PATH = CONFIGURATION_DIR / "manager.sock"
