from typing import List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import DomainName, IPAddressOptionalPort
from knot_resolver_manager.datamodel.types.files import FilePath
from knot_resolver_manager.utils.modeling import ConfigSchema


class ForwardServerSchema(ConfigSchema):
    """
    Forward server configuration options.

    ---
    address: IP address(es) of a forward server.
    transport: Transport protocol for a forward server.
    pin_sha256: Hash of accepted CA certificate.
    hostname: Hostname of the Forward server.
    ca_file: Path to CA certificate file.
    """

    address: Union[IPAddressOptionalPort, List[IPAddressOptionalPort]]
    transport: Optional[Literal["tls"]] = None
    pin_sha256: Optional[Union[str, List[str]]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[FilePath] = None


class ForwardOptionsSchema(ConfigSchema):
    """
    Configuration options for forward subtree.

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
    subtree: Subtree to forward.
    servers: Forward server configuration.
    options: Configuration options for forward subtree.
    """

    subtree: DomainName
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    options: ForwardOptionsSchema = ForwardOptionsSchema()
