# ruff: noqa: E501
from typing import List, Optional

from knot_resolver.datamodel.types import DomainName, EscapedStr, ReadableFile
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
    enable: Enable/disable DNSSEC.
    log_bogus: Enable logging for each DNSSEC validation failure if '/logging/level' is set to at least 'notice'.
    sentinel: Allows users of DNSSEC validating resolver to detect which root keys are configured in resolver's chain of trust. (RFC 8509)
    signal_query: Signaling Trust Anchor Knowledge in DNSSEC Using Key Tag Query, according to (RFC 8145#section-5).
    trust_anchors: List of trust-anchors in DS/DNSKEY records format.
    trust_anchors_files: List of zone-files where trust-anchors are stored.
    trust_anchors: Trust-anchors configuration.
    negative_trust_anchors: List of domain names representing negative trust-anchors. (RFC 7646)
    """

    enable: bool = True
    log_bogus: bool = False
    sentinel: bool = True
    signal_query: bool = True
    trust_anchors: Optional[List[EscapedStr]] = None
    trust_anchors_files: Optional[List[TrustAnchorFileSchema]] = None
    negative_trust_anchors: Optional[List[DomainName]] = None
