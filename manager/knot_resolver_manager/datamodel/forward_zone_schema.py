from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import CheckedPath, DomainName, IPAddressOptionalPort, PolicyFlagEnum
from knot_resolver_manager.utils import SchemaNode


class ForwardServerSchema(SchemaNode):
    """
    Configuration of Forward server.

    ---
    address: IP address of Forward server.
    pin_sha256: Hash of accepted CA certificate.
    hostname: Hostname of the Forward server.
    ca_file: Path to CA certificate file.
    """

    address: IPAddressOptionalPort
    pin_sha256: Optional[Union[str, List[str]]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[CheckedPath] = None


class ForwardZoneSchema(SchemaNode):
    """
    Configuration of Forward Zone.

    ---
    tls: Enable/disable TLS for Forward servers.
    servers: IP address of Forward server.
    views: Use this Forward Zone only for clients defined by views.
    options: Configuration flags for Forward Zone.
    """

    tls: bool = False
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
