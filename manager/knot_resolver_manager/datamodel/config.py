from typing import Optional

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .cache_config import CacheConfig
from .dns64_config import Dns64Config
from .logging_config import LoggingConfig
from .lua_config import LuaConfig
from .network_config import NetworkConfig
from .server_config import ServerConfig


@dataclass
class KresConfig(DataclassParserValidatorMixin):
    server: ServerConfig = ServerConfig()
    network: Optional[NetworkConfig] = None
    cache: CacheConfig = CacheConfig()
    dns64: Optional[Dns64Config] = None
    logging: LoggingConfig = LoggingConfig()
    lua: LuaConfig = LuaConfig()

    def validate(self):
        self.server.validate()
        if self.network is not None:
            self.network.validate()
        self.cache.validate()
        if self.dns64 is not None:
            self.dns64.validate()
        self.logging.validate()
        self.lua.validate()
