from typing import List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import DomainName, File, IPAddressOptionalPort, ListOrItem, PinSha256
from knot_resolver_manager.utils.modeling import ConfigSchema


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
    ca_file: Optional[File] = None

    def _validate(self) -> None:
        if self.pin_sha256 and (self.hostname or self.ca_file):
            raise ValueError("'pin-sha256' cannot be configurad together with 'hostname' or 'ca-file'")


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
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    options: ForwardOptionsSchema = ForwardOptionsSchema()
