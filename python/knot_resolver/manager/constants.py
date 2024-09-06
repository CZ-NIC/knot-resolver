from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from knot_resolver.controller.interface import KresID
    from knot_resolver.datamodel.config_schema import KresConfig
    from knot_resolver.manager.config_store import ConfigStore


def kres_cache_dir(config: "KresConfig") -> Path:
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
