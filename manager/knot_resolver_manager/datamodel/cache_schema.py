from typing import List, Optional

from knot_resolver_manager.datamodel.types import CheckedPath, SizeUnit, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class PrefillSchema(SchemaNode):
    domain: str
    url: str
    refresh_interval: TimeUnit = TimeUnit("1d")
    ca_file: Optional[CheckedPath] = None


class CacheSchema(SchemaNode):
    storage: CheckedPath = CheckedPath("/var/cache/knot-resolver")
    size_max: SizeUnit = SizeUnit("100M")
    ttl_min: TimeUnit = TimeUnit("5s")
    ttl_max: TimeUnit = TimeUnit("6d")
    ns_timeout: TimeUnit = TimeUnit("1000ms")
    prefill: Optional[List[PrefillSchema]] = None

    def _validate(self):
        if self.ttl_min.seconds() >= self.ttl_max.seconds():
            raise ValueError("'ttl-max' must be larger then 'ttl-min'")
