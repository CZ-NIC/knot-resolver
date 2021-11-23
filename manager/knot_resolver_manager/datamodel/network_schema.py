from typing import List, Optional

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    IPAddress,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    Listen,
    SizeUnit,
)
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

KindEnum = LiteralEnum["dns", "xdp", "dot", "doh"]


class InterfaceSchema(SchemaNode):
    listen: Listen
    kind: KindEnum = "dns"
    freebind: bool = False


class EdnsBufferSizeSchema(SchemaNode):
    upstream: SizeUnit = SizeUnit("1232B")
    downstream: SizeUnit = SizeUnit("1232B")


class AddressRenumberingSchema(SchemaNode):
    source: IPNetwork
    destination: IPAddress


class TLSSchema(SchemaNode):
    cert_file: Optional[CheckedPath] = None
    key_file: Optional[CheckedPath] = None
    sticket_secret: Optional[str] = None
    sticket_secret_file: Optional[CheckedPath] = None
    auto_discovery: bool = False
    padding: int = 1

    def _validate(self):
        if self.sticket_secret and self.sticket_secret_file:
            raise ValueError("'sticket_secret' and 'sticket_secret_file' are both defined, only one can be used")
        if not 0 <= self.padding <= 512:
            raise ValueError("'padding' must be number in range<0-512>")


class NetworkSchema(SchemaNode):
    do_ipv4: bool = True
    do_ipv6: bool = True
    out_interface_v4: Optional[IPv4Address] = None
    out_interface_v6: Optional[IPv6Address] = None
    tcp_pipeline: int = 100
    edns_keep_alive: bool = True
    edns_buffer_size: EdnsBufferSizeSchema = EdnsBufferSizeSchema()
    address_renumbering: Optional[List[AddressRenumberingSchema]] = None
    tls: TLSSchema = TLSSchema()
    interfaces: List[InterfaceSchema] = [
        InterfaceSchema({"listen": {"ip": "127.0.0.1", "port": 53}}),
        InterfaceSchema({"listen": {"ip": "::1", "port": 53}, "freebind": True}),
    ]

    def _validate(self):
        if self.tcp_pipeline < 0:
            raise ValueError("'tcp-pipeline' must be nonnegative number")
