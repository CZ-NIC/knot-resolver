import pkgutil
from typing import Text, Union

from jinja2 import Environment, Template

from knot_resolver_manager.datamodel.dns64_config import Dns64, Dns64Strict
from knot_resolver_manager.datamodel.lua_config import Lua, LuaStrict
from knot_resolver_manager.datamodel.network_config import Network, NetworkStrict
from knot_resolver_manager.datamodel.server_config import Server, ServerStrict
from knot_resolver_manager.utils import DataParser, DataValidator


def _import_lua_template() -> Template:
    env = Environment(trim_blocks=True, lstrip_blocks=True)
    template = pkgutil.get_data("knot_resolver_manager.datamodel", "lua_template.j2")
    if template is None:
        raise OSError("package cannot be located or loaded")
    return env.from_string(template.decode("utf-8"))


_LUA_TEMPLATE = _import_lua_template()


class KresConfig(DataParser):
    server: Server = Server()
    network: Network = Network()
    dns64: Union[bool, Dns64] = False
    lua: Lua = Lua()


class KresConfigStrict(DataValidator):
    server: ServerStrict
    network: NetworkStrict
    dns64: Union[bool, Dns64Strict]
    lua: LuaStrict

    def _dns64(self, obj: KresConfig) -> Union[bool, Dns64]:
        if obj.dns64 is True:
            return Dns64()
        return obj.dns64

    def render_lua(self) -> Text:
        return _LUA_TEMPLATE.render(cfg=self)

    def _validate(self) -> None:
        pass
