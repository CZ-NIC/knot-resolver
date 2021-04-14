from typing import Optional

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .cache_config import CacheConfig
from .dns64_config import Dns64Config
from .dnssec_config import DnssecConfig
from .hints_config import StaticHintsConfig
from .logging_config import LoggingConfig
from .lua_config import LuaConfig
from .network_config import NetworkConfig
from .options_config import OptionsConfig
from .server_config import ServerConfig


@dataclass
class KresConfig(DataclassParserValidatorMixin):
    # pylint: disable=too-many-instance-attributes
    server: ServerConfig = ServerConfig()
    options: OptionsConfig = OptionsConfig()
    network: Optional[NetworkConfig] = None
    static_hints: StaticHintsConfig = StaticHintsConfig()
    dnssec: Optional[DnssecConfig] = None
    cache: CacheConfig = CacheConfig()
    dns64: Optional[Dns64Config] = None
    logging: LoggingConfig = LoggingConfig()
    lua: LuaConfig = LuaConfig()

    def validate(self):
        self.server.validate()
        self.options.validate()
        if self.network is not None:
            self.network.validate()
        self.static_hints.validate()
        if self.dnssec is not None:
            self.dnssec.validate()
        self.cache.validate()
        if self.dns64 is not None:
            self.dns64.validate()
        self.logging.validate()
        self.lua.validate()
