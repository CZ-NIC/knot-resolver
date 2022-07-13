from typing import List, Optional, Union

from knot_resolver_manager.datamodel.policy_schema import ForwardServerSchema
from knot_resolver_manager.datamodel.types import DomainName, IPAddressOptionalPort, PolicyFlagEnum
from knot_resolver_manager.utils.modeling import BaseSchema


class ForwardZoneSchema(BaseSchema):
    """
    Configuration of Forward Zone.

    ---
    name: Domain name of the zone.
    tls: Enable/disable TLS for Forward servers.
    servers: IP address of Forward server.
    views: Use this Forward Zone only for clients defined by views.
    options: Configuration flags for Forward Zone.
    """

    name: DomainName
    tls: bool = False
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
