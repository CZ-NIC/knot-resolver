from typing import List, Optional, Union

from knot_resolver_manager.datamodel.policy_schema import ForwardServerSchema
from knot_resolver_manager.datamodel.types import DomainName, IPAddressOptionalPort, PolicyFlagEnum
from knot_resolver_manager.utils.modeling import ConfigSchema


class ForwardZoneSchema(ConfigSchema):
    """
    Configuration of Forward Zone.

    ---
    subtree: Domain name of the zone.
    servers: IP address of Forward server.
    views: Use this Forward Zone only for clients defined by views.
    options: Configuration flags for Forward Zone.
    """

    subtree: DomainName
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
