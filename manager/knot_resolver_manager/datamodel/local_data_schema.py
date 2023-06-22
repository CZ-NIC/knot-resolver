from typing import Dict, List, Optional

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import DomainName, File, IDPattern, IPAddress, ListOrItem, TimeUnit
from knot_resolver_manager.utils.modeling import ConfigSchema


class SubtreeSchema(ConfigSchema):
    """
    Local data and configuration of subtree.

    ---
    type: Type of the subtree.
    tags: Tags to link with other policy rules.
    ttl: Default TTL value used for added local subtree.
    nodata: Use NODATA synthesis. NODATA will be synthesised for matching name, but mismatching type(e.g. AAAA query when only A exists).
    addresses: Subtree addresses.
    roots: Subtree roots.
    roots_file: Subtree roots from given file.
    roots_url: Subtree roots form given URL.
    refresh: Refresh time to update data from 'roots-file' or 'roots-url'.
    """

    type: Literal["empty", "nxdomain", "redirect"]
    tags: Optional[List[IDPattern]] = None
    ttl: Optional[TimeUnit] = None
    nodata: bool = True
    addresses: Optional[List[IPAddress]] = None
    roots: Optional[List[DomainName]] = None
    roots_file: Optional[File] = None
    roots_url: Optional[str] = None
    refresh: Optional[TimeUnit] = None

    def _validate(self) -> None:
        options_sum = sum([bool(self.roots), bool(self.roots_file), bool(self.roots_url)])
        if options_sum > 1:
            raise ValueError("only one of, 'roots', 'roots-file' or 'roots-url' can be configured")
        elif options_sum < 1:
            raise ValueError("one of, 'roots', 'roots-file' or 'roots-url' must be configured")
        if self.refresh and not (self.roots_file or self.roots_url):
            raise ValueError("'refresh' can be only configured with 'roots-file' or 'roots-url'")


class RPZSchema(ConfigSchema):
    """
    Configuration or Response Policy Zone (RPZ).

    ---
    file: Path to the RPZ zone file.
    tags: Tags to link with other policy rules.
    """

    file: File
    tags: Optional[List[IDPattern]] = None


class LocalDataSchema(ConfigSchema):
    """
    Local data for forward records (A/AAAA) and reverse records (PTR).

    ---
    ttl: Default TTL value used for added local data/records.
    nodata: Use NODATA synthesis. NODATA will be synthesised for matching name, but mismatching type(e.g. AAAA query when only A exists).
    root_fallback_addresses: Direct replace of root hints.
    root_fallback_addresses_files: Direct replace of root hints from a zonefile.
    addresses: Direct addition of hostname and IP addresses pairs.
    addresses_files: Direct addition of hostname and IP addresses pairs from files in '/etc/hosts' like format.
    records: Direct addition of records in DNS zone file format.
    subtrees: Direct addition of subtrees.
    rpz: List of Response Policy Zones and its configuration.
    """

    ttl: Optional[TimeUnit] = None
    nodata: bool = True
    root_fallback_addresses: Optional[Dict[DomainName, ListOrItem[IPAddress]]] = None
    root_fallback_addresses_files: Optional[ListOrItem[File]] = None
    addresses: Optional[Dict[DomainName, IPAddress]] = None
    addresses_files: Optional[ListOrItem[File]] = None
    records: Optional[str] = None
    subtrees: Optional[List[SubtreeSchema]] = None
    rpz: Optional[List[RPZSchema]] = None
