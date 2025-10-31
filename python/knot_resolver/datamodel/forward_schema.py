from typing import Any, List, Literal, Optional, Union

from knot_resolver.datamodel.types import DomainName, IPAddressOptionalPort, ListOrItem, PinSha256, ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class ForwardServerSchema(ConfigSchema):
    """
    Forward server configuration.

    ---
    address: IP address(es) of a forward server.
    transport: Transport protocol for a forward server.
    pin_sha256: Hash of accepted CA certificate.
    hostname: Hostname of the Forward server.
    ca_file: Path to CA certificate file.
    """

    address: ListOrItem[IPAddressOptionalPort]
    transport: Optional[Literal["tls"]] = None
    pin_sha256: Optional[ListOrItem[PinSha256]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[ReadableFile] = None

    def _validate(self) -> None:
        if self.pin_sha256 and (self.hostname or self.ca_file):
            raise ValueError("'pin-sha256' cannot be configured together with 'hostname' or 'ca-file'")


class ForwardOptionsSchema(ConfigSchema):
    """
    Subtree(s) forward options.

    ---
    authoritative: The forwarding target is an authoritative server.
    dnssec: Enable/disable DNSSEC.
    """

    authoritative: bool = False
    dnssec: bool = True


class ForwardSchema(ConfigSchema):
    """
    Configuration of forward subtree.

    ---
    subtree: Subtree(s) to forward.
    servers: Forward servers configuration.
    options: Subtree(s) forward options.
    """

    subtree: ListOrItem[DomainName]
    servers: List[Union[IPAddressOptionalPort, ForwardServerSchema]]
    options: ForwardOptionsSchema = ForwardOptionsSchema()

    def _validate(self) -> None:
        def is_port_custom(servers: List[Any]) -> bool:
            for server in servers:
                if isinstance(server, IPAddressOptionalPort) and server.port:
                    return int(server.port) != 53
                if isinstance(server, ForwardServerSchema):
                    return is_port_custom(server.address.to_std())
            return False

        def is_transport_tls(servers: List[Any]) -> bool:
            for server in servers:
                if isinstance(server, ForwardServerSchema):
                    return server.transport == "tls"
            return False

        if self.options.authoritative and is_port_custom(self.servers):
            raise ValueError("Forwarding to authoritative servers on a custom port is currently not supported.")

        if self.options.authoritative and is_transport_tls(self.servers):
            raise ValueError("Forwarding to authoritative servers using TLS protocol is not supported.")


class FallbackSchema(ConfigSchema):
    """
    Configuration for fallback after resolution failure.

    ---
    enable: Enable/disable the fallback.
    servers: Forward servers configuration for fallback.
    """

    enable: bool = False
    servers: Optional[List[Union[IPAddressOptionalPort, ForwardServerSchema]]] = None

    def _validate(self) -> None:
        if self.enable and self.servers is None:
            raise ValueError("Fallback enabled without configuring servers.")
