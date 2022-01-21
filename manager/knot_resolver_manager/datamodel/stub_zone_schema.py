from typing import List, Optional, Union

from knot_resolver_manager.datamodel.types import FlagsEnum, IPAddressOptionalPort
from knot_resolver_manager.utils import SchemaNode


class StubServerSchema(SchemaNode):
    address: IPAddressOptionalPort


class StubZoneSchema(SchemaNode):
    servers: Union[List[IPAddressOptionalPort], List[StubServerSchema]]
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
