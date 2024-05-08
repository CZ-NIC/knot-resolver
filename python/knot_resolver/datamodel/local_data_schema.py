from typing import Any, Dict, List, Literal, Optional, Union

from knot_resolver.constants import WATCHDOG_LIB
from knot_resolver.datamodel.types import (
    DomainName,
    EscapedStr,
    IDPattern,
    IPAddress,
    ListOrItem,
    ReadableFile,
    TimeUnit,
)
from knot_resolver.utils.modeling import ConfigSchema


class RuleSchema(ConfigSchema):
    """
    Local data advanced rule configuration.

    ---
    name: Hostname(s).
    subtree: Type of subtree.
    address: Address(es) to pair with hostname(s).
    file: Path to file(s) with hostname and IP address(es) pairs in '/etc/hosts' like format.
    records: Direct addition of records in DNS zone file format.
    tags: Tags to link with other policy rules.
    ttl: Optional, TTL value used for these answers.
    nodata: Optional, use NODATA synthesis. NODATA will be synthesised for matching name, but mismatching type(e.g. AAAA query when only A exists).
    """

    name: Optional[ListOrItem[DomainName]] = None
    subtree: Optional[Literal["empty", "nxdomain", "redirect"]] = None
    address: Optional[ListOrItem[IPAddress]] = None
    file: Optional[ListOrItem[ReadableFile]] = None
    records: Optional[EscapedStr] = None
    tags: Optional[List[IDPattern]] = None
    ttl: Optional[TimeUnit] = None
    nodata: Optional[bool] = None
    # TODO: probably also implement the rule options from RPZSchema (.log + .dry_run)

    def _validate(self) -> None:
        options_sum = sum([bool(self.address), bool(self.subtree), bool(self.file), bool(self.records)])
        if options_sum == 2 and bool(self.address) and self.subtree in {"empty", "redirect"}:
            pass  # these combinations still make sense
        elif options_sum > 1:
            raise ValueError("only one of 'address', 'subtree' or 'file' can be configured")
        elif options_sum < 1:
            raise ValueError("one of 'address', 'subtree', 'file' or 'records' must be configured")

        options_sum2 = sum([bool(self.name), bool(self.file), bool(self.records)])
        if options_sum2 != 1:
            raise ValueError("one of 'name', 'file or 'records' must be configured")

        if bool(self.nodata) and bool(self.subtree) and not bool(self.address):
            raise ValueError("'nodata' defined but unused with 'subtree'")


class RPZSchema(ConfigSchema):
    class Raw(ConfigSchema):
        """
        Configuration or Response Policy Zone (RPZ).

        ---
        file: Path to the RPZ zone file.
        watchdog: Enables files watchdog for configured RPZ file. Requires the optional 'watchdog' dependency.
        tags: Tags to link with other policy rules.
        log: Enables logging information whenever this RPZ matches.
        """

        file: ReadableFile
        watchdog: Union[Literal["auto"], bool] = "auto"
        tags: Optional[List[IDPattern]] = None
        log: Optional[List[Literal["ip", "name"]]] = None
        # dry_run: bool = False

    _LAYER = Raw

    file: ReadableFile
    watchdog: bool
    tags: Optional[List[IDPattern]]
    log: Optional[List[Literal["ip", "name"]]]
    # dry_run: bool

    def _watchdog(self, obj: Raw) -> Any:
        if obj.watchdog == "auto":
            return WATCHDOG_LIB
        return obj.watchdog

    def _validate(self) -> None:
        if self.watchdog and not WATCHDOG_LIB:
            raise ValueError(
                "'watchdog' is enabled, but the required 'watchdog' dependency (optional) is not installed"
            )


class LocalDataSchema(ConfigSchema):
    """
    Local data for forward records (A/AAAA) and reverse records (PTR).

    ---
    ttl: Default TTL value used for added local data/records.
    nodata: Use NODATA synthesis. NODATA will be synthesised for matching name, but mismatching type(e.g. AAAA query when only A exists).
    addresses: Direct addition of hostname and IP addresses pairs.
    addresses_files: Direct addition of hostname and IP addresses pairs from files in '/etc/hosts' like format.
    records: Direct addition of records in DNS zone file format.
    rules: Local data rules.
    rpz: List of Response Policy Zones and its configuration.
    """

    ttl: Optional[TimeUnit] = None
    nodata: bool = True
    addresses: Optional[Dict[DomainName, ListOrItem[IPAddress]]] = None
    addresses_files: Optional[List[ReadableFile]] = None
    records: Optional[EscapedStr] = None
    rules: Optional[List[RuleSchema]] = None
    rpz: Optional[List[RPZSchema]] = None
    # root_fallback_addresses*: removed, rarely useful
