from typing import List

from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

KindEnum = LiteralEnum["dns", "xdp", "dot", "doh"]


class Interface(SchemaNode):
    listen: str
    kind: KindEnum = "dns"
    freebind: bool = False


class InterfaceStrict(SchemaNode):
    address: str
    port: int
    kind: str
    freebind: bool

    def _address(self, obj: Interface) -> str:
        if "@" in obj.listen:
            address = obj.listen.split("@", maxsplit=1)[0]
            return address
        return obj.listen

    def _port(self, obj: Interface) -> int:
        port_map = {"dns": 53, "xdp": 53, "dot": 853, "doh": 443}
        if "@" in obj.listen:
            port = obj.listen.split("@", maxsplit=1)[1]
            return int(port)
        return port_map.get(obj.kind, 0)


class Network(SchemaNode):
    interfaces: List[Interface] = [Interface({"listen": "127.0.0.1"}), Interface({"listen": "::1", "freebind": True})]


class NetworkStrict(SchemaNode):
    interfaces: List[InterfaceStrict]
