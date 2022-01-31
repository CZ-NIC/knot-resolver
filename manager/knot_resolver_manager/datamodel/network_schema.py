from typing import List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    InterfaceOptionalPort,
    IPAddress,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    PortNumber,
    SizeUnit,
)
from knot_resolver_manager.utils import SchemaNode

KindEnum = Literal["dns", "xdp", "dot", "doh-legacy", "doh2"]


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


class ListenSchema(SchemaNode):
    class Raw(SchemaNode):
        interface: Union[None, InterfaceOptionalPort, List[InterfaceOptionalPort]] = None
        unix_socket: Union[None, CheckedPath, List[CheckedPath]] = None
        port: Optional[PortNumber] = None
        kind: KindEnum = "dns"
        freebind: bool = False

    _PREVIOUS_SCHEMA = Raw

    interface: Union[None, InterfaceOptionalPort, List[InterfaceOptionalPort]]
    unix_socket: Union[None, CheckedPath, List[CheckedPath]]
    port: Optional[PortNumber]
    kind: KindEnum
    freebind: bool

    def _interface(self, origin: Raw) -> Union[None, InterfaceOptionalPort, List[InterfaceOptionalPort]]:
        if isinstance(origin.interface, list):
            port_set: Optional[bool] = None
            for intrfc in origin.interface:
                if origin.port and intrfc.port:
                    raise ValueError("The port number is defined in two places ('port' option and '@<port>' syntax).")
                if port_set is not None and (bool(intrfc.port) != port_set):
                    raise ValueError(
                        "The '@<port>' syntax must be used either for all or none of the interface in the list."
                    )
                port_set = bool(intrfc.port)
        elif isinstance(origin.interface, InterfaceOptionalPort) and origin.interface.port and origin.port:
            raise ValueError("The port number is defined in two places ('port' option and '@<port>' syntax).")
        return origin.interface

    def _port(self, origin: Raw) -> Optional[PortNumber]:
        if origin.port:
            return origin.port
        # default port number based on kind
        elif origin.interface:
            if origin.kind == "dot":
                return PortNumber(853)
            elif origin.kind in ["doh-legacy", "doh2"]:
                return PortNumber(443)
            return PortNumber(53)
        return None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")
        if self.port and self.unix_socket:
            raise ValueError(
                "'unix-socket' and 'port' are not compatible options."
                " Port configuration can only be used with 'interface' option."
            )


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
    listen: List[ListenSchema] = [
        ListenSchema({"interface": "127.0.0.1"}),
        ListenSchema({"interface": "::1", "freebind": True}),
    ]

    def _validate(self):
        if self.tcp_pipeline < 0:
            raise ValueError("'tcp-pipeline' must be nonnegative number")
