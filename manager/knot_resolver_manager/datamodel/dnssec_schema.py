from typing import List, Optional

from knot_resolver_manager.datamodel.types import TimeUnit
from knot_resolver_manager.utils import SchemaNode


class TrustAnchorFileSchema(SchemaNode):
    file: str
    read_only: bool = False


class DnssecSchema(SchemaNode):
    trust_anchor_sentinel: bool = True
    trust_anchor_signal_query: bool = True
    time_skew_detection: bool = True
    keep_removed: int = 0
    refresh_time: Optional[TimeUnit] = None
    hold_down_time: TimeUnit = TimeUnit("30d")

    trust_anchors: Optional[List[str]] = None
    negative_trust_anchors: Optional[List[str]] = None
    trust_anchors_files: Optional[List[TrustAnchorFileSchema]] = None
