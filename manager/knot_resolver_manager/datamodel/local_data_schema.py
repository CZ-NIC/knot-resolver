from typing import Dict, List, Optional

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    DomainName,
    EscapedStr,
    File,
    IDPattern,
    IPAddress,
    ListOrItem,
    TimeUnit,
)
from knot_resolver_manager.utils.modeling import ConfigSchema


class RuleSchema(ConfigSchema):
    """
    Local data rule configuration.

    ---
    name: Hostname(s).
    address: Address(es) to pair with hostname(s).
    file: Path to file(s) with hostname and IP address(es) pairs in '/etc/hosts' like format.
    subtree: Type of subtree.
    tags: Tags to link with other policy rules.
    ttl: Optional, TTL value used for these answers.
    nodata: Optional, use NODATA synthesis. NODATA will be synthesised for matching name, but mismatching type(e.g. AAAA query when only A exists).
    """

    name: Optional[ListOrItem[DomainName]] = None
    address: Optional[ListOrItem[IPAddress]] = None
    subtree: Optional[Literal["empty", "nxdomain", "redirect"]] = None
    file: Optional[ListOrItem[File]] = None
    tags: Optional[List[IDPattern]] = None
    ttl: Optional[TimeUnit] = None
    nodata: Optional[bool] = None

    def _validate(self) -> None:
        options_sum = sum([bool(self.address), bool(self.subtree), bool(self.file)])
        if options_sum == 2 and bool(self.address) and self.subtree in {"empty", "redirect"}:
            pass # these combinations still make sense
        elif options_sum > 1:
            raise ValueError("only one of 'address', 'subtree' or 'file' can be configured")
        elif options_sum < 1:
            raise ValueError("one of 'address', 'subtree' or 'file' must be configured")

        if bool(self.file) == bool(self.name):
            raise ValueError("one of 'file' or 'name' must be configured")

        if bool(self.nodata) and bool(self.subtree) and not bool(self.address):
            raise ValueError("'nodata' defined but unused with 'subtree'")


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
    rules: Local data rules.
    rpz: List of Response Policy Zones and its configuration.
    """

    ttl: Optional[TimeUnit] = None
    nodata: bool = True
    root_fallback_addresses: Optional[Dict[DomainName, ListOrItem[IPAddress]]] = None
    root_fallback_addresses_files: Optional[List[File]] = None
    addresses: Optional[Dict[DomainName, ListOrItem[IPAddress]]] = None
    addresses_files: Optional[List[File]] = None
    records: Optional[EscapedStr] = None
    rules: Optional[List[RuleSchema]] = None
    rpz: Optional[List[RPZSchema]] = None
