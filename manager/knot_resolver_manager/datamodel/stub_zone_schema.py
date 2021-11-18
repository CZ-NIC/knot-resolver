from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPAddressPort
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode


class StubZoneSchema(SchemaNode):
    name: str
    servers: List[IPAddressPort]
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
