from typing import Dict, List, Optional

from knot_resolver_manager.datamodel.types import CheckedPath, DomainName, IPAddress, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class StaticHintsSchema(SchemaNode):
    """
    Static hints for forward records (A/AAAA) and reverse records (PTR)

    ---
    ttl: TTL value used for records added from static hints.
    nodata: Use NODATA synthesis. NODATA will be synthesised for matching hint name, but mismatching type.
    etc_hosts: Add hints from '/etc/hosts' file.
    root_hints: Direct addition of root hints pairs (hostname, list of addresses).
    root_hints_file: Path to root hints in zonefile. Replaces all current root hints.
    hints: Direct addition of hints pairs (hostname, list of addresses).
    hints_files: Path to hints in hosts-like file.
    """

    ttl: Optional[TimeUnit] = None
    nodata: bool = True
    etc_hosts: bool = False
    root_hints: Optional[Dict[DomainName, List[IPAddress]]] = None
    root_hints_file: Optional[CheckedPath] = None
    hints: Optional[Dict[DomainName, List[IPAddress]]] = None
    hints_files: Optional[List[CheckedPath]] = None
