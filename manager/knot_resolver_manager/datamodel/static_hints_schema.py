from typing import Dict, List, Optional

from knot_resolver_manager.datamodel.types import CheckedPath, DomainName, IPAddress, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class StaticHintsSchema(SchemaNode):
    ttl: Optional[TimeUnit] = None
    no_data: bool = True
    etc_hosts: bool = False
    root_hints_file: Optional[CheckedPath] = None
    hints_files: Optional[List[CheckedPath]] = None
    root_hints: Optional[Dict[DomainName, List[IPAddress]]] = None
    hints: Optional[Dict[DomainName, List[IPAddress]]] = None
