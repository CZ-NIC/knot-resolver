from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import AnyPath, DomainName, IPAddressPort
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode


class ForwardServerSchema(SchemaNode):
    address: IPAddressPort
    pin_sha256: Optional[Union[str, List[str]]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[AnyPath] = None


class ForwardZoneSchema(SchemaNode):
    name: DomainName
    tls: bool = False
    servers: Union[List[IPAddressPort], List[ForwardServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
