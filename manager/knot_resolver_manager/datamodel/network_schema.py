from typing import List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    InterfaceOptionalPort,
    IPAddress,
    IPAddressOptionalPort,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    PortNumber,
    SizeUnit,
)
from knot_resolver_manager.utils import SchemaNode

KindEnum = Literal["dns", "xdp", "dot", "doh2"]


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
        unix_socket: Union[None, CheckedPath, List[CheckedPath]] = None
        ip_address: Union[None, IPAddressOptionalPort, List[IPAddressOptionalPort]] = None
        interface: Union[None, InterfaceOptionalPort, List[InterfaceOptionalPort]] = None
        port: Optional[PortNumber] = None
        kind: KindEnum = "dns"
        freebind: bool = False

    _PREVIOUS_SCHEMA = Raw

    unix_socket: Union[None, CheckedPath, List[CheckedPath]]
    ip_address: Union[None, IPAddressOptionalPort, List[IPAddressOptionalPort]]
    interface: Union[None, InterfaceOptionalPort, List[InterfaceOptionalPort]]
    port: Optional[PortNumber]
    kind: KindEnum
    freebind: bool

    def _ip_address(self, origin: Raw) -> Union[None, IPAddressOptionalPort, List[IPAddressOptionalPort]]:
        if isinstance(origin.ip_address, list):
            port_set: Optional[bool] = None
            for addr in origin.ip_address:
                if origin.port and addr.port:
                    raise ValueError("The port number is defined in two places ('port' option and '@<port>' syntax).")
                if port_set is not None and (bool(addr.port) != port_set):
                    raise ValueError(
                        "The '@<port>' syntax must be used either for all or none of the IP addresses in the list."
                    )
                port_set = bool(addr.port)
        elif isinstance(origin.ip_address, IPAddressOptionalPort) and origin.ip_address.port and origin.port:
            raise ValueError("The port number is defined in two places ('port' option and '@<port>' syntax).")
        return origin.ip_address

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
        elif origin.ip_address or origin.interface:
            if origin.kind == "dot":
                return PortNumber(853)
            elif origin.kind == "doh2":
                return PortNumber(443)
            return PortNumber(53)
        return None

    def _validate(self) -> None:
        present = {
            "ip_address" if self.ip_address is not None else ...,
            "unix_socket" if self.unix_socket is not None else ...,
            "interface" if self.interface is not None else ...,
        }
        if not (present == {"ip_address", ...} or present == {"unix_socket", ...} or present == {"interface", ...}):
            raise ValueError(
                "Listen configuration contains multiple incompatible options at once. "
                "Only one of 'ip-address', 'interface' and 'unix-socket' optionscan be configured at once."
            )
        if self.port and self.unix_socket:
            raise ValueError(
                "'unix-socket' and 'port' are not compatible options. "
                "Port configuration can only be used with 'ip-address' or 'interface'."
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
        ListenSchema({"ip-address": "127.0.0.1"}),
        ListenSchema({"ip-address": "::1", "freebind": True}),
    ]

    def _validate(self):
        if self.tcp_pipeline < 0:
            raise ValueError("'tcp-pipeline' must be nonnegative number")
