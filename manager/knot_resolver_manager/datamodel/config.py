import pkgutil
from typing import Text, Union

from jinja2 import Environment, Template
from typing_extensions import Literal

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
    class Raw(SchemaNode):
        server: Server = Server()
        options: Options = Options()
        network: Network = Network()
        dnssec: Union[bool, Dnssec] = True
        dns64: Union[bool, Dns64] = False
        lua: Lua = Lua()

    _PREVIOUS_SCHEMA = Raw

    server: Server
    options: Options
    network: Network
    dnssec: Union[Literal[False], Dnssec]
    dns64: Union[Literal[False], Dns64]
    lua: Lua

    def _dnssec(self, obj: Raw) -> Union[Literal[False], Dnssec]:
        if obj.dnssec is True:
            return Dnssec()
        return obj.dnssec

    def _dns64(self, obj: Raw) -> Union[Literal[False], Dns64]:
        if obj.dns64 is True:
            return Dns64()
        return obj.dns64

    def render_lua(self) -> Text:
        return _LUA_TEMPLATE.render(cfg=self)
