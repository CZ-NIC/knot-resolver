from typing import List, Optional

from knot_resolver_manager.datamodel.types import TimeUnit
from knot_resolver_manager.utils import SchemaNode


class TrustAnchorFile(SchemaNode):
    file: str
    read_only: bool = False


class Dnssec(SchemaNode):
    trust_anchor_sentinel: bool = True
    trust_anchor_signal_query: bool = True
    time_skew_detection: bool = True
    keep_removed: int = 0
    refresh_time: Optional[TimeUnit] = None
    hold_down_time: TimeUnit = TimeUnit("30d")

    trust_anchors: Optional[List[str]] = None
    negative_trust_anchors: Optional[List[str]] = None
    trust_anchors_files: Optional[List[TrustAnchorFile]] = None


class TrustAnchorFileStrict(SchemaNode):
    file: str
    read_only: bool


class DnssecStrict(SchemaNode):
    trust_anchor_sentinel: bool
    trust_anchor_signal_query: bool
    time_skew_detection: bool
    keep_removed: int
    refresh_time: Optional[TimeUnit]
    hold_down_time: TimeUnit

    trust_anchors: Optional[List[str]]
    negative_trust_anchors: Optional[List[str]]
    trust_anchors_files: Optional[List[TrustAnchorFileStrict]]
