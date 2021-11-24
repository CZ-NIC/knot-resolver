from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPNetwork
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

# TODO: FLAGS from https://knot-resolver.readthedocs.io/en/stable/lib.html?highlight=options#c.kr_qflags
FlagsEnum = LiteralEnum["no-cache", "no-edns"]


class ViewSchema(SchemaNode):
    addresses: Optional[List[IPNetwork]] = None
    tsig: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None

    def _validate(self) -> None:
        if self.tsig is None and self.addresses is None:
            raise ValueError("one of 'address' or 'rsig' must be configured")
