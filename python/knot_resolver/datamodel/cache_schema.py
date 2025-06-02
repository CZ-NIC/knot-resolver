from typing import List, Optional

from knot_resolver.constants import CACHE_DIR
from knot_resolver.datamodel.templates import template_from_str
from knot_resolver.datamodel.types import (
    DNSRecordTypeEnum,
    DomainName,
    EscapedStr,
    IntNonNegative,
    IntPositive,
    Percent,
    ReadableFile,
    SizeUnit,
    TimeUnit,
    WritableDir,
)
from knot_resolver.utils.modeling import ConfigSchema
from knot_resolver.utils.modeling.base_schema import lazy_default

_CACHE_CLEAR_TEMPLATE = template_from_str(
    "{% from 'macros/cache_macros.lua.j2' import cache_clear %} {{ cache_clear(params) }}"
)


class CacheClearRPCSchema(ConfigSchema):
    name: Optional[DomainName] = None
    exact_name: bool = False
    rr_type: Optional[DNSRecordTypeEnum] = None
    chunk_size: IntPositive = IntPositive(100)

    def _validate(self) -> None:
        if self.rr_type and not self.exact_name:
            raise ValueError("'rr-type' is only supported with 'exact-name: true'")

    def render_lua(self) -> str:
        return _CACHE_CLEAR_TEMPLATE.render(params=self)  # pyright: reportUnknownMemberType=false


class PrefillSchema(ConfigSchema):
    """
    Prefill the cache periodically by importing zone data obtained over HTTP.

    ---
    origin: Origin for the imported data. Cache prefilling is only supported for the root zone ('.').
    url: URL of the zone data to be imported.
    refresh_interval: Time interval between consecutive refreshes of the imported zone data.
    ca_file: Path to the file containing a CA certificate bundle that is used to authenticate the HTTPS connection.
    """

    origin: DomainName
    url: EscapedStr
    refresh_interval: TimeUnit = TimeUnit("1d")
    ca_file: Optional[ReadableFile] = None

    def _validate(self) -> None:
        if str(self.origin) != ".":
            raise ValueError("cache prefilling is not yet supported for non-root zones")


class GarbageCollectorSchema(ConfigSchema):
    """
    Configuration options of the cache garbage collector (kres-cache-gc).

    ---
    enabled: Enable/disable cache garbage collector.
    interval: Time interval how often the garbage collector will be run.
    threshold: Cache usage in percent that triggers the garbage collector.
    release: Percent of used cache to be freed by the garbage collector.
    temp_keys_space: Maximum amount of temporary memory for copied keys (0 = unlimited).
    rw_deletes: Maximum number of deleted records per read-write transaction (0 = unlimited).
    rw_reads: Maximum number of read records per read-write transaction (0 = unlimited).
    rw_duration: Maximum duration of read-write transaction (0 = unlimited).
    rw_delay: Wait time between two read-write transactions.
    dry_run: Run the garbage collector in dry-run mode.
    """

    enabled: bool = True
    interval: TimeUnit = TimeUnit("1s")
    threshold: Percent = Percent(80)
    release: Percent = Percent(10)
    temp_keys_space: SizeUnit = SizeUnit("0M")
    rw_deletes: IntNonNegative = IntNonNegative(100)
    rw_reads: IntNonNegative = IntNonNegative(200)
    rw_duration: TimeUnit = TimeUnit("0us")
    rw_delay: TimeUnit = TimeUnit("0us")
    dry_run: bool = False


class PredictionSchema(ConfigSchema):
    """
    Helps keep the cache hot by prefetching expiring records and learning usage patterns and repetitive queries.

    ---
    window: Sampling window length.
    period: Number of windows that can be kept in memory.
    """

    window: TimeUnit = TimeUnit("15m")
    period: IntPositive = IntPositive(24)


class PrefetchSchema(ConfigSchema):
    """
    These options help keep the cache hot by prefetching expiring records or learning usage patterns and repetitive queries.
    ---
    expiring: Prefetch expiring records.
    prediction: Prefetch record by predicting based on usage patterns and repetitive queries.
    """

    expiring: bool = False
    prediction: Optional[PredictionSchema] = None


class CacheSchema(ConfigSchema):
    """
    DNS resolver cache configuration.

    ---
    storage: Cache storage of the DNS resolver.
    size_max: Maximum size of the cache.
    garbage_collector: Use the garbage collector (kres-cache-gc) to periodically clear cache.
    ttl_min: Minimum time-to-live for the cache entries.
    ttl_max: Maximum time-to-live for the cache entries.
    ns_timeout: Time interval for which a nameserver address will be ignored after determining that it does not return (useful) answers.
    prefill: Prefill the cache periodically by importing zone data obtained over HTTP.
    prefetch: These options help keep the cache hot by prefetching expiring records or learning usage patterns and repetitive queries.
    """

    storage: WritableDir = lazy_default(WritableDir, str(CACHE_DIR))
    size_max: SizeUnit = SizeUnit("100M")
    garbage_collector: GarbageCollectorSchema = GarbageCollectorSchema()
    ttl_min: TimeUnit = TimeUnit("5s")
    ttl_max: TimeUnit = TimeUnit("1d")
    ns_timeout: TimeUnit = TimeUnit("1000ms")
    prefill: Optional[List[PrefillSchema]] = None
    prefetch: PrefetchSchema = PrefetchSchema()

    def _validate(self):
        if self.ttl_min.seconds() > self.ttl_max.seconds():
            raise ValueError("'ttl-max' can't be smaller than 'ttl-min'")
