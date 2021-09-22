from typing import List

from knot_resolver_manager.datamodel.types import Listen
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

KindEnum = LiteralEnum["dns", "xdp", "dot", "doh"]


class InterfaceSchema(SchemaNode):
    listen: Listen
    kind: KindEnum = "dns"
    freebind: bool = False


class NetworkSchema(SchemaNode):
    interfaces: List[InterfaceSchema] = [
        InterfaceSchema({"listen": {"ip": "127.0.0.1", "port": 53}}),
        InterfaceSchema({"listen": {"ip": "::1", "port": 53}, "freebind": True}),
    ]
