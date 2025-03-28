from typing import List, Optional

from knot_resolver.datamodel.types import DomainName, EscapedStr, IntNonNegative, ReadableFile
from knot_resolver.utils.modeling import ConfigSchema


class TrustAnchorFileSchema(ConfigSchema):
    """
    Trust-anchor zonefile configuration.

    ---
    file: Path to the zonefile that stores trust-anchors.
    read_only: Blocks zonefile updates according to RFC 5011.

    """

    file: ReadableFile
    read_only: bool = False


class DnssecSchema(ConfigSchema):
    """
    DNSSEC configuration.

    ---
    trust_anchor_sentinel: Allows users of DNSSEC validating resolver to detect which root keys are configured in resolver's chain of trust. (RFC 8509)
    trust_anchor_signal_query: Signaling Trust Anchor Knowledge in DNSSEC Using Key Tag Query, according to (RFC 8145#section-5).
    time_skew_detection: Detection of difference between local system time and expiration time bounds in DNSSEC signatures for '. NS' records.
    keep_removed: How many removed keys should be held in history (and key file) before being purged.
    trust_anchors: List of trust-anchors in DS/DNSKEY records format.
    negative_trust_anchors: List of domain names representing negative trust-anchors. (RFC 7646)
    trust_anchors_files: List of zone-files where trust-anchors are stored.
    """

    trust_anchor_sentinel: bool = True
    trust_anchor_signal_query: bool = True
    time_skew_detection: bool = True
    keep_removed: IntNonNegative = IntNonNegative(0)
    trust_anchors: Optional[List[EscapedStr]] = None
    negative_trust_anchors: Optional[List[DomainName]] = None
    trust_anchors_files: Optional[List[TrustAnchorFileSchema]] = None
