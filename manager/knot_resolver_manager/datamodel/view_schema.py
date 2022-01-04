from typing import List, Optional

from knot_resolver_manager.datamodel.types import FlagsEnum, IPNetwork
from knot_resolver_manager.utils import SchemaNode


class ViewSchema(SchemaNode):
    subnets: Optional[List[IPNetwork]] = None
    tsig: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None

    def _validate(self) -> None:
        if self.tsig is None and self.subnets is None:
            raise ValueError("'subnets' or 'rsig' must be configured")
