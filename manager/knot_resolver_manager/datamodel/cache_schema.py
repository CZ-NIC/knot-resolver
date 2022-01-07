from typing import List, Optional

from knot_resolver_manager.datamodel.types import CheckedPath, DomainName, SizeUnit, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class PrefillSchema(SchemaNode):
    """
    Prefill the cache periodically by importing zone data obtained over HTTP.

    ---
    origin: Origin for the imported data. Cache prefilling is only supported for the root zone ('.').
    url: URL of the zone file to be imported.
    refresh_interval: Time interval between consecutive refreshes of the imported zone data.
    ca_file: Path to the file containing a CA certificate bundle that is used to authenticate the HTTPS connection.
    """

    origin: DomainName
    url: str
    refresh_interval: TimeUnit = TimeUnit("1d")
    ca_file: Optional[CheckedPath] = None

    def _validate(self) -> None:
        if self.origin != ".":
            raise ValueError("cache prefilling is not yet supported for non-root zones")


class CacheSchema(SchemaNode):
    """
    DNS resolver cache configuration.

    ---
    storage: DNS resolver cache storage.
    size_max: Maximum size of the cache.
    ttl_min: Minimum time-to-live for cache entries.
    ttl_max: Maximum time-to-live for cache entries.
    ns_timeout: Time interval for which a nameserver address will be ignored after determining that it does not return (useful) answers.
    prefill: Prefill the cache periodically by importing zone data obtained over HTTP.
    """

    storage: CheckedPath = CheckedPath("/var/cache/knot-resolver")
    size_max: SizeUnit = SizeUnit("100M")
    ttl_min: TimeUnit = TimeUnit("5s")
    ttl_max: TimeUnit = TimeUnit("6d")
    ns_timeout: TimeUnit = TimeUnit("1000ms")
    prefill: Optional[List[PrefillSchema]] = None

    def _validate(self):
        if self.ttl_min.seconds() >= self.ttl_max.seconds():
            raise ValueError("'ttl-max' must be larger then 'ttl-min'")
