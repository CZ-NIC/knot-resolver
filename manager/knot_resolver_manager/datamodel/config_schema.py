import os
import sys
from typing import Dict, Optional, Union

from jinja2 import Environment, FileSystemLoader, Template
from typing_extensions import Literal

from knot_resolver_manager.datamodel.cache_schema import CacheSchema
from knot_resolver_manager.datamodel.dns64_schema import Dns64Schema
from knot_resolver_manager.datamodel.dnssec_schema import DnssecSchema
from knot_resolver_manager.datamodel.forward_zone import ForwardZoneSchema
from knot_resolver_manager.datamodel.logging_config import LoggingSchema
from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.datamodel.network_schema import NetworkSchema
from knot_resolver_manager.datamodel.options_schema import OptionsSchema
from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.datamodel.server_schema import ServerSchema
from knot_resolver_manager.datamodel.static_hints_schema import StaticHintsSchema
from knot_resolver_manager.datamodel.stub_zone_schema import StubZoneSchema
from knot_resolver_manager.datamodel.types import DomainName
from knot_resolver_manager.datamodel.view_schema import ViewSchema
from knot_resolver_manager.utils import SchemaNode


def _get_templates_dir() -> str:
    module = sys.modules["knot_resolver_manager.datamodel"].__file__
    if module:
        templates_dir = os.path.join(os.path.dirname(module), "templates")
        if os.path.isdir(templates_dir):
            return templates_dir
        raise NotADirectoryError(f"the templates dir '{templates_dir}' is not a directory or does not exist")
    raise OSError("package 'knot_resolver_manager.datamodel' cannot be located or loaded")


_TEMPLATES_DIR = _get_templates_dir()


def template_from_str(template: str) -> Template:
    ldr = FileSystemLoader(_TEMPLATES_DIR)
    env = Environment(trim_blocks=True, lstrip_blocks=True, loader=ldr)
    return env.from_string(template)


def _import_lua_template() -> Template:
    path = os.path.join(_TEMPLATES_DIR, "config.lua.j2")
    with open(path, "r", encoding="UTF-8") as file:
        template = file.read()
    return template_from_str(template)


_MAIN_TEMPLATE = _import_lua_template()


class KresConfig(SchemaNode):
    """
    Knot Resolver declarative configuration.

    ---
    server: DNS server control and management configuration.
    options: Fine-tuning global parameters of DNS resolver operation.
    network: Network connections and protocols.
    static_hints: Static hints configuration section.
    views: List of views and its configuration.
    policy: List of policy rules and its configuration.
    rpz: List of Response Policy Zones and its configuration.
    stub_zones: List of Stub Zones and its configuration.
    forward_zones: List of Forward Zones and its configuration.
    cache: DNS resolver cache configuration.
    dnssec: DNSSEC disabling/enabling and configuration.
    dns64: DNS64 disabling/enabling and configuration.
    logging: Logging and debugging configuration.
    lua: Custom Lua configuration.
    """

    class Raw(SchemaNode):
        server: ServerSchema = ServerSchema()
        options: OptionsSchema = OptionsSchema()
        network: NetworkSchema = NetworkSchema()
        static_hints: StaticHintsSchema = StaticHintsSchema()
        views: Optional[Dict[str, ViewSchema]] = None
        policy: Optional[Dict[str, PolicySchema]] = None
        rpz: Optional[Dict[str, RPZSchema]] = None
        stub_zones: Optional[Dict[DomainName, StubZoneSchema]] = None
        forward_zones: Optional[Dict[DomainName, ForwardZoneSchema]] = None
        cache: CacheSchema = CacheSchema()
        dnssec: Union[bool, DnssecSchema] = True
        dns64: Union[bool, Dns64Schema] = False
        logging: LoggingSchema = LoggingSchema()
        lua: LuaSchema = LuaSchema()

    _PREVIOUS_SCHEMA = Raw

    server: ServerSchema
    options: OptionsSchema
    network: NetworkSchema
    static_hints: StaticHintsSchema
    views: Optional[Dict[str, ViewSchema]]
    policy: Optional[Dict[str, PolicySchema]]
    rpz: Optional[Dict[str, RPZSchema]]
    stub_zones: Optional[Dict[DomainName, StubZoneSchema]]
    forward_zones: Optional[Dict[DomainName, ForwardZoneSchema]]
    cache: CacheSchema
    dnssec: Union[Literal[False], DnssecSchema]
    dns64: Union[Literal[False], Dns64Schema]
    logging: LoggingSchema
    lua: LuaSchema

    def _dnssec(self, obj: Raw) -> Union[Literal[False], DnssecSchema]:
        if obj.dnssec is True:
            return DnssecSchema()
        return obj.dnssec

    def _dns64(self, obj: Raw) -> Union[Literal[False], Dns64Schema]:
        if obj.dns64 is True:
            return Dns64Schema()
        return obj.dns64

    def render_lua(self) -> str:
        return _MAIN_TEMPLATE.render(cfg=self)  # pyright: reportUnknownMemberType=false
