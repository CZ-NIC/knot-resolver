from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import CheckedPath, DomainName, IPAddressOptionalPort, PolicyFlagEnum
from knot_resolver_manager.utils import SchemaNode


class ForwardServerSchema(SchemaNode):
    address: IPAddressOptionalPort
    pin_sha256: Optional[Union[str, List[str]]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[CheckedPath] = None


class ForwardZoneSchema(SchemaNode):
    tls: bool = False
    servers: Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
