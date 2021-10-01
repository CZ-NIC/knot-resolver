from typing import List, Optional

from knot_resolver_manager.datamodel.types import AnyPath, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class Hint(SchemaNode):
    name: str
    addresses: List[str]


class StaticHintsSchema(SchemaNode):
    ttl: Optional[TimeUnit] = None
    no_data: bool = True
    etc_hosts: bool = False
    root_hints_file: Optional[AnyPath] = None
    hints_files: Optional[List[AnyPath]] = None
    root_hints: Optional[List[Hint]] = None
    hints: Optional[List[Hint]] = None
