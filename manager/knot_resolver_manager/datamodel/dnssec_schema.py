from typing import List, Optional

from knot_resolver_manager.datamodel.types import TimeUnit
from knot_resolver_manager.utils import SchemaNode


class TrustAnchorFileSchema(SchemaNode):
    """
    Trust-anchor zonefile configuration.

    ---
    file: Path to the zonefile that stores trust-anchors.
    read_only: Blocks zonefile updates according to RFC 5011.

    """

    file: str
    read_only: bool = False


class DnssecSchema(SchemaNode):
    """
    DNSSEC configuration.

    ---
    trust_anchor_sentinel: Allows users of DNSSEC validating resolver to detect which root keys are configured in resolver's chain of trust. (RFC 8509)
    trust_anchor_signal_query: Signaling Trust Anchor Knowledge in DNSSEC Using Key Tag Query, according to (RFC 8145#section-5).
    time_skew_detection: Detection of difference between local system time and expiration time bounds in DNSSEC signatures for '. NS' records.
    keep_removed: How many removed keys should be held in history (and key file) before being purged.
    refresh_time: Force trust-anchors to be updated every defined time periodically instead of relying on (RFC 5011) logic and TTLs. Intended only for testing purposes.
    hold_down_time: Modify hold-down timer (RFC 5011). Intended only for testing purposes.
    trust_anchors: List of trust-anchors in DS/DNSKEY records format.
    negative_trust_anchors: List of domain names representing negative trust-anchors. (RFC 7646)
    trust_anchors_files: List of zonefiles where trust-anchors are stored.
    """

    trust_anchor_sentinel: bool = True
    trust_anchor_signal_query: bool = True
    time_skew_detection: bool = True
    keep_removed: int = 0
    refresh_time: Optional[TimeUnit] = None
    hold_down_time: TimeUnit = TimeUnit("30d")
    trust_anchors: Optional[List[str]] = None
    negative_trust_anchors: Optional[List[str]] = None
    trust_anchors_files: Optional[List[TrustAnchorFileSchema]] = None
