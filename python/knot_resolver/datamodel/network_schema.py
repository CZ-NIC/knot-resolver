from typing import Any, List, Literal, Optional, Union

from knot_resolver.constants import WATCHDOG_LIB
from knot_resolver.datamodel.types import (
    EscapedStr32B,
    Int0_512,
    Int0_65535,
    InterfaceOptionalPort,
    IPAddress,
    IPAddressEM,
    IPNetwork,
    IPv4Address,
    IPv6Address,
    ListOrItem,
    PortNumber,
    ReadableFile,
    SizeUnit,
    WritableFilePath,
)
from knot_resolver.utils.modeling import ConfigSchema

KindEnum = Literal["dns", "xdp", "dot", "doh-legacy", "doh2"]


class EdnsBufferSizeSchema(ConfigSchema):
    """
    EDNS payload size advertised in DNS packets.

    ---
    upstream: Maximum EDNS upstream (towards other DNS servers) payload size.
    downstream: Maximum EDNS downstream (towards clients) payload size for communication.
    """

    upstream: SizeUnit = SizeUnit("1232B")
    downstream: SizeUnit = SizeUnit("1232B")


class AddressRenumberingSchema(ConfigSchema):
    """
    Renumbers addresses in answers to different address space.

    ---
    source: Source subnet.
    destination: Destination address prefix.
    """

    source: IPNetwork
    destination: Union[IPAddressEM, IPAddress]


class TLSSchema(ConfigSchema):
    class Raw(ConfigSchema):
        """
        TLS configuration, also affects DNS over TLS and DNS over HTTPS.

        ---
        watchdog: Enables watchdog of changes in TLS certificate files. Requires the optional 'watchdog' dependency.
        cert_file: Path to certificate file.
        key_file: Path to certificate key file.
        sticket_secret: Secret for TLS session resumption via tickets. (RFC 5077).
        sticket_secret_file: Path to file with secret for TLS session resumption via tickets. (RFC 5077).
        padding: EDNS(0) padding of queries and answers sent over an encrypted channel.
        """

        watchdog: Union[Literal["auto"], bool] = "auto"
        cert_file: Optional[ReadableFile] = None
        key_file: Optional[ReadableFile] = None
        sticket_secret: Optional[EscapedStr32B] = None
        sticket_secret_file: Optional[ReadableFile] = None
        padding: Union[bool, Int0_512] = True

    _LAYER = Raw

    watchdog: bool
    cert_file: Optional[ReadableFile] = None
    key_file: Optional[ReadableFile] = None
    sticket_secret: Optional[EscapedStr32B] = None
    sticket_secret_file: Optional[ReadableFile] = None
    padding: Union[bool, Int0_512] = True

    def _watchdog(self, obj: Raw) -> Any:
        if obj.watchdog == "auto":
            return WATCHDOG_LIB
        return obj.watchdog

    def _validate(self):
        if self.sticket_secret and self.sticket_secret_file:
            raise ValueError("'sticket_secret' and 'sticket_secret_file' are both defined, only one can be used")
        if bool(self.cert_file) != bool(self.key_file):
            raise ValueError("'cert-file' and 'key-file' must be configured together")
        if self.cert_file and self.key_file and self.watchdog and not WATCHDOG_LIB:
            raise ValueError(
                "'files-watchdog' is enabled, but the required 'watchdog' dependency (optional) is not installed"
            )


class ListenSchema(ConfigSchema):
    class Raw(ConfigSchema):
        """
        Configuration of listening interface.

        ---
        unix_socket: Path to unix domain socket to listen to.
        interface: IP address or interface name with optional port number to listen to.
        port: Port number to listen to.
        kind: Specifies DNS query transport protocol.
        freebind: Used for binding to non-local address.
        """

        interface: Optional[ListOrItem[InterfaceOptionalPort]] = None
        unix_socket: Optional[ListOrItem[WritableFilePath]] = None
        port: Optional[PortNumber] = None
        kind: KindEnum = "dns"
        freebind: bool = False

    _LAYER = Raw

    interface: Optional[ListOrItem[InterfaceOptionalPort]]
    unix_socket: Optional[ListOrItem[WritableFilePath]]
    port: Optional[PortNumber]
    kind: KindEnum
    freebind: bool

    def _interface(self, origin: Raw) -> Optional[ListOrItem[InterfaceOptionalPort]]:
        if origin.interface:
            port_set: Optional[bool] = None
            for intrfc in origin.interface:  # type: ignore[attr-defined]
                if origin.port and intrfc.port:
                    raise ValueError("The port number is defined in two places ('port' option and '@<port>' syntax).")
                if port_set is not None and (bool(intrfc.port) != port_set):
                    raise ValueError(
                        "The '@<port>' syntax must be used either for all or none of the interface in the list."
                    )
                port_set = bool(intrfc.port)
        return origin.interface

    def _port(self, origin: Raw) -> Optional[PortNumber]:
        if origin.port:
            return origin.port
        # default port number based on kind
        if origin.interface:
            if origin.kind == "dot":
                return PortNumber(853)
            if origin.kind in ["doh-legacy", "doh2"]:
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


class ProxyProtocolSchema(ConfigSchema):
    """
    PROXYv2 protocol configuration.

    ---
    allow: Allow usage of the PROXYv2 protocol headers by clients on the specified addresses.
    """

    allow: List[Union[IPAddress, IPNetwork]]


class NetworkSchema(ConfigSchema):
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
    proxy_protocol: PROXYv2 protocol configuration.
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
    proxy_protocol: Union[Literal[False], ProxyProtocolSchema] = False
    listen: List[ListenSchema] = [
        ListenSchema({"interface": "127.0.0.1"}),
        ListenSchema({"interface": "::1", "freebind": True}),
    ]
