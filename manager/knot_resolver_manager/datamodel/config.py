import pkgutil
from typing import Any, Text, Union

from jinja2 import Environment, Template

from knot_resolver_manager.datamodel.dns64_config import Dns64
from knot_resolver_manager.datamodel.dnssec_config import Dnssec
from knot_resolver_manager.datamodel.lua_config import Lua
from knot_resolver_manager.datamodel.network_config import Network
from knot_resolver_manager.datamodel.options_config import Options
from knot_resolver_manager.datamodel.server_config import Server
from knot_resolver_manager.utils import SchemaNode


def _import_lua_template() -> Template:
    env = Environment(trim_blocks=True, lstrip_blocks=True)
    template = pkgutil.get_data("knot_resolver_manager.datamodel", "lua_template.j2")
    if template is None:
        raise OSError("package cannot be located or loaded")
    return env.from_string(template.decode("utf-8"))


_LUA_TEMPLATE = _import_lua_template()


class KresConfig(SchemaNode):
    server: Server = Server()
    options: Options = Options()
    network: Network = Network()
    dnssec: Union[bool, Dnssec] = True
    dns64: Union[bool, Dns64] = False
    lua: Lua = Lua()

    def _dnssec(self, obj: Any) -> Union[bool, Dnssec]:
        if "dnssec" not in obj or obj["dnssec"] is True:
            return Dnssec()
        return obj["dnssec"]

    def _dns64(self, obj: Any) -> Union[bool, Dns64]:
        if "dns64" not in obj or obj["dns64"] is True:
            return Dns64()
        return obj["dns64"]

    def render_lua(self) -> Text:
        return _LUA_TEMPLATE.render(cfg=self)
