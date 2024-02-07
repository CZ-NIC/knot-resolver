from typing import Any, List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    Dir,
    DNSRecordTypeEnum,
    DomainName,
    EscapedStr,
    File,
    IntNonNegative,
    IntPositive,
    Percent,
    SizeUnit,
    TimeUnit,
)
from knot_resolver_manager.utils.modeling import ConfigSchema
from knot_resolver_manager.utils.modeling.base_schema import lazy_default


class CacheClearRPCSchema(ConfigSchema):
    name: Optional[DomainName] = None
    exact_name: bool = False
    rr_type: Optional[DNSRecordTypeEnum] = None
    chunk_size: IntPositive = IntPositive(100)


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
    ca_file: Optional[File] = None

    def _validate(self) -> None:
        if str(self.origin) != ".":
            raise ValueError("cache prefilling is not yet supported for non-root zones")


class GarbageCollectorSchema(ConfigSchema):
    """
    Configuration options of the cache garbage collector (kres-cache-gc).

    ---
    interval: Time interval how often the garbage collector will be run.
    threshold: Cache usage in percent that triggers the garbage collector.
    release: Percent of used cache to be freed by the garbage collector.
    temp_keys_space: Maximum amount of temporary memory for copied keys (0 = unlimited).
    rw_deletes: Maximum number of deleted records per read-write transaction (0 = unlimited).
    rw_reads: Maximum number of readed records per read-write transaction (0 = unlimited).
    rw_duration: Maximum duration of read-write transaction (0 = unlimited).
    rw_delay: Wait time between two read-write transactions.
    dry_run: Run the garbage collector in dry-run mode.
    """

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
    period: IntNonNegative = IntNonNegative(24)


class CacheSchema(ConfigSchema):
    class Raw(ConfigSchema):
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
        prediction: Helps keep the cache hot by prefetching expiring records and learning usage patterns and repetitive queries.
        """

        storage: Dir = lazy_default(Dir, "/var/cache/knot-resolver")
        size_max: SizeUnit = SizeUnit("100M")
        garbage_collector: Union[GarbageCollectorSchema, Literal[False]] = GarbageCollectorSchema()
        ttl_min: TimeUnit = TimeUnit("5s")
        ttl_max: TimeUnit = TimeUnit("1d")
        ns_timeout: TimeUnit = TimeUnit("1000ms")
        prefill: Optional[List[PrefillSchema]] = None
        prediction: Union[bool, PredictionSchema] = False

    _LAYER = Raw

    storage: Dir
    size_max: SizeUnit
    garbage_collector: Union[GarbageCollectorSchema, Literal[False]]
    ttl_min: TimeUnit
    ttl_max: TimeUnit
    ns_timeout: TimeUnit
    prefill: Optional[List[PrefillSchema]]
    prediction: Union[Literal[False], PredictionSchema]

    def _prediction(self, obj: Raw) -> Any:
        if obj.prediction is True:
            return PredictionSchema()
        return obj.prediction

    def _validate(self):
        if self.ttl_min.seconds() >= self.ttl_max.seconds():
            raise ValueError("'ttl-max' must be larger then 'ttl-min'")
