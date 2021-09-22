import pkgutil
from typing import Text, Union

from jinja2 import Environment, Template
from typing_extensions import Literal

from knot_resolver_manager.datamodel.dns64_config import Dns64Schema
from knot_resolver_manager.datamodel.dnssec_config import DnssecSchema
from knot_resolver_manager.datamodel.lua_config import LuaSchema
from knot_resolver_manager.datamodel.network_config import NetworkSchema
from knot_resolver_manager.datamodel.options_config import OptionsSchema
from knot_resolver_manager.datamodel.server_config import ServerSchema
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
        server: ServerSchema = ServerSchema()
        options: OptionsSchema = OptionsSchema()
        network: NetworkSchema = NetworkSchema()
        dnssec: Union[bool, DnssecSchema] = True
        dns64: Union[bool, Dns64Schema] = False
        lua: LuaSchema = LuaSchema()

    _PREVIOUS_SCHEMA = Raw

    server: ServerSchema
    options: OptionsSchema
    network: NetworkSchema
    dnssec: Union[Literal[False], DnssecSchema]
    dns64: Union[Literal[False], Dns64Schema]
    lua: LuaSchema

    def _dnssec(self, obj: Raw) -> Union[Literal[False], DnssecSchema]:
        if obj.dnssec is True:
            return DnssecSchema()
        return obj.dnssec

    def _dns64(self, obj: Raw) -> Union[Literal[False], Dns64Schema]:
        if obj.dns64 is True:
            return Dns64Schema()
        return obj.dns64

    def render_lua(self) -> Text:
        return _LUA_TEMPLATE.render(cfg=self)
