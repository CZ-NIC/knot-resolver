from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import FlagsEnum, IPAddressPort
from knot_resolver_manager.utils import SchemaNode


class StubServerSchema(SchemaNode):
    address: IPAddressPort


class StubZoneSchema(SchemaNode):
    servers: Union[List[IPAddressPort], List[StubServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
