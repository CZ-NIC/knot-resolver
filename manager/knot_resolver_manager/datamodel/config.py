from typing import Optional, Union

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .cache_config import CacheConfig
from .dns64_config import Dns64Config
from .logging_config import LoggingConfig
from .lua_config import LuaConfig
from .network_config import NetworkConfig
from .options_config import OptionsConfig
from .server_config import ServerConfig


@dataclass
class KresConfig(DataclassParserValidatorMixin):
    # pylint: disable=too-many-instance-attributes
    server: ServerConfig = ServerConfig()
    network: NetworkConfig = NetworkConfig()
    options: OptionsConfig = OptionsConfig()
    cache: CacheConfig = CacheConfig()
    # DNS64 is disabled by default
    dns64: Union[bool, Dns64Config] = False
    logging: LoggingConfig = LoggingConfig()
    lua: Optional[LuaConfig] = None

    def __post_init__(self):
        # if DNS64 is enabled with defaults
        if self.dns64 is True:
            self.dns64 = Dns64Config()

    def _validate(self):
        pass
