import pkgutil
from typing import Optional, Text, Union

from jinja2 import Environment, Template

from knot_resolver_manager.compat.dataclasses import dataclass
from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin

from .cache_config import CacheConfig
from .dns64_config import Dns64Config
from .logging_config import LoggingConfig
from .lua_config import LuaConfig
from .network_config import NetworkConfig
from .options_config import OptionsConfig
from .server_config import ServerConfig


def _import_lua_template() -> Template:
    env = Environment(trim_blocks=True, lstrip_blocks=True)
    template = pkgutil.get_data("knot_resolver_manager.datamodel", "lua_template.j2")
    if template is None:
        raise OSError("package cannot be located or loaded")
    return env.from_string(template.decode("utf-8"))


_LUA_TEMPLATE = _import_lua_template()


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

    def render_lua(self) -> Text:
        return _LUA_TEMPLATE.render(cfg=self)
