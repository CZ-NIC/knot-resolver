from typing import List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    Int0_512,
    Int0_65535,
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
    """
    EDNS payload size advertised in DNS packets.

    ---
    upstream: Maximum EDNS upstream (towards other DNS servers) payload size.
    downstream: Maximum EDNS downstream (towards clients) payload size for communication.
    """

    upstream: SizeUnit = SizeUnit("1232B")
    downstream: SizeUnit = SizeUnit("1232B")


class AddressRenumberingSchema(SchemaNode):
    """
    Renumbers addresses in answers to different address space.

    ---
    source: Source subnet.
    destination: Destination address prefix.
    """

    source: IPNetwork
    destination: IPAddress


class TLSSchema(SchemaNode):
    """
    TLS configuration, also affects DNS over TLS and DNS over HTTPS.

    ---
    cert_file: Path to certificate file.
    key_file: Path to certificate key file.
    sticket_secret: Secret for TLS session resumption via tickets. (RFC 5077).
    sticket_secret_file: Path to file with secret for TLS session resumption via tickets. (RFC 5077).
    auto_discovery: Automatic discovery of authoritative servers supporting DNS-over-TLS.
    padding: EDNS(0) padding of answers to queries that arrive over TLS transport.
    """

    cert_file: Optional[CheckedPath] = None
    key_file: Optional[CheckedPath] = None
    sticket_secret: Optional[str] = None
    sticket_secret_file: Optional[CheckedPath] = None
    auto_discovery: bool = False
    padding: Union[bool, Int0_512] = True

    def _validate(self):
        if self.sticket_secret and self.sticket_secret_file:
            raise ValueError("'sticket_secret' and 'sticket_secret_file' are both defined, only one can be used")


class ListenSchema(SchemaNode):
    class Raw(SchemaNode):
        """
        Configuration of listening interface.

        ---
        unix_socket: Path to unix domain socket to listen to.
        interface: IP address or interface name with optional port number to listen to.
        port: Port number to listen to.
        kind: Specifies DNS query transport protocol.
        freebind: Used for binding to non-local address.
        """

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
    """
    Network connections and protocols configuration.

    ---
    do_ipv4: Enable/disable using IPv4 for contacting upstream nameservers.
    do_ipv6: Enable/disable using IPv6 for contacting upstream nameservers.
    out_interface_v4: IPv4 address used to perform queries. Not set by default, which lets the OS choose any address.
    out_interface_v6: IPv6 address used to perform queries. Not set by default, which lets the OS choose any address.
    tcp_pipeline: TCP pipeline limit. The number of outstanding queries that a single client connection can make in parallel.
    edns_tcp_keepalive: Allows clients to discover the connection timeout. (RFC 7828)
    edns_buffer_size: Maximum EDNS payload size advertised in DNS packets. Different values can be configured for communication downstream (towards clients) and upstream (towards other DNS servers).
    address_renumbering: Renumbers addresses in answers to different address space.
    tls: TLS configuration, also affects DNS over TLS and DNS over HTTPS.
    listen: List of interfaces to listen to and its configuration.
    """

    do_ipv4: bool = True
    do_ipv6: bool = True
    out_interface_v4: Optional[IPv4Address] = None
    out_interface_v6: Optional[IPv6Address] = None
    tcp_pipeline: Int0_65535 = Int0_65535(100)
    edns_tcp_keepalive: bool = True
    edns_buffer_size: EdnsBufferSizeSchema = EdnsBufferSizeSchema()
    address_renumbering: Optional[List[AddressRenumberingSchema]] = None
    tls: TLSSchema = TLSSchema()
    listen: List[ListenSchema] = [
        ListenSchema({"interface": "127.0.0.1"}),
        ListenSchema({"interface": "::1", "freebind": True}),
    ]
