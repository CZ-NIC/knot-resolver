import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Generator, List, Optional, Tuple, TypeVar

from prometheus_client import Histogram, exposition  # type: ignore
from prometheus_client.bridge.graphite import GraphiteBridge  # type: ignore
from prometheus_client.core import (  # type: ignore
    REGISTRY,
    CounterMetricFamily,
    GaugeMetricFamily,
    HistogramMetricFamily,
    Metric,
)

from knot_resolver_manager import compat
from knot_resolver_manager.config_store import ConfigStore, only_on_real_changes
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.kres_id import KresID
from knot_resolver_manager.kresd_controller.interface import Subprocess
from knot_resolver_manager.utils.functional import Result

logger = logging.getLogger(__name__)

MANAGER_REQUEST_RECONFIGURE_LATENCY = Histogram(
    "manager_request_reconfigure_latency", "Time it takes to change configuration"
)

_REGISTERED_RESOLVERS: Dict[KresID, Subprocess] = {}


T = TypeVar("T")


def async_timing_histogram(metric: Histogram) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """
    Decorator which can be used to report duration on async functions
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            with metric.time():
                res = await func(*args, **kwargs)
                return res

        return wrapper

    return decorator


async def _command_registered_resolvers(cmd: str) -> Dict[KresID, str]:
    async def single_pair(sub: Subprocess) -> Tuple[KresID, str]:
        return sub.id, await sub.command(cmd)

    pairs = await asyncio.gather(*(single_pair(inst) for inst in _REGISTERED_RESOLVERS.values()))
    return dict(pairs)


def _counter(name: str, description: str, label: Tuple[str, str], value: float) -> CounterMetricFamily:
    c = CounterMetricFamily(name, description, labels=(label[0],))
    c.add_metric(label[1], value)  # type: ignore
    return c


def _gauge(name: str, description: str, label: Tuple[str, str], value: float) -> GaugeMetricFamily:
    c = GaugeMetricFamily(name, description, labels=(label[0],))
    c.add_metric(label[1], value)  # type: ignore
    return c


def _histogram(
    name: str, description: str, label: Tuple[str, str], buckets: List[Tuple[str, int]], sum_value: float
) -> HistogramMetricFamily:
    c = HistogramMetricFamily(name, description, labels=(label[0],))
    c.add_metric(label[1], buckets, sum_value=sum_value)  # type: ignore
    return c


class ResolverCollector:
    def __init__(self, config_store: ConfigStore) -> None:
        self._stats_raw: Optional[Dict[KresID, str]] = None
        self._config_store: ConfigStore = config_store
        self._collection_task: "Optional[asyncio.Task[None]]" = None
        self._skip_immediate_collection: bool = False

    async def collect_kresd_stats(self, _triggered_from_prometheus_library: bool = False) -> None:
        if self._skip_immediate_collection:
            # this would happen because we are calling this function first manually before stat generation,
            # and once again immediately afterwards caused by the prometheus library's stat collection
            #
            # this is a code made to solve problem with calling async functions from sync methods
            self._skip_immediate_collection = False
            return

        config = self._config_store.get()

        if config.monitoring.enabled == "manager-only":
            logger.debug("Skipping kresd stat collection due to configuration")
            self._stats_raw = None
            return

        lazy = config.monitoring.enabled == "lazy"
        cmd = "collect_lazy_statistics()" if lazy else "collect_statistics()"
        logger.debug("Collecting kresd stats with method '%s'", cmd)
        stats_raw = await _command_registered_resolvers(cmd)
        self._stats_raw = stats_raw

        # if this function was not called by the prometheus library and calling collect() is imminent,
        # we should block the next collection cycle as it would be useless
        if not _triggered_from_prometheus_library:
            self._skip_immediate_collection = True

    def _trigger_stats_collection(self) -> None:
        # we are running inside an event loop, but in a synchronous function and that sucks a lot
        # it means that we shouldn't block the event loop by performing a blocking stats collection
        # but it also means that we can't yield to the event loop as this function is synchronous
        # therefore we can only start a new task, but we can't wait for it
        # which causes the metrics to be delayed by one collection pass (not the best, but probably good enough)
        #
        # this issue can be prevented by calling the `collect_kresd_stats()` function manually before entering
        # the Prometheus library. We just have to prevent the library from invoking it again. See the mentioned
        # function for details
        if self._collection_task is not None and not self._collection_task.done():
            logger.warning("Statistics collection task is still running. Skipping scheduling of a new one!")
        else:
            self._collection_task = compat.asyncio.create_task(
                self.collect_kresd_stats(_triggered_from_prometheus_library=True)
            )

    def _create_resolver_metrics_loaded_gauge(self, kid: KresID, loaded: bool) -> GaugeMetricFamily:
        return _gauge(
            "resolver_metrics_loaded",
            "0 if metrics from resolver instance were not loaded, otherwise 1",
            label=("instance_id", str(kid)),
            value=int(loaded),
        )

    def collect(self) -> Generator[Metric, None, None]:
        # schedule new stats collection
        self._trigger_stats_collection()

        # if we have no data, return metrics with information about it and exit
        if self._stats_raw is None:
            for kid in _REGISTERED_RESOLVERS:
                yield self._create_resolver_metrics_loaded_gauge(kid, False)
            return

        # if we have data, parse them
        for kid in _REGISTERED_RESOLVERS:
            success = False
            try:
                if kid in self._stats_raw:
                    raw = self._stats_raw[kid]
                    metrics: Dict[str, int] = json.loads(raw[1:-1])
                    yield from self._parse_resolver_metrics(kid, metrics)
                    success = True
            except json.JSONDecodeError:
                logger.warning("Failed to load metrics from resolver instance %s: failed to parse statistics", str(kid))
            except KeyError as e:
                logger.warning(
                    "Failed to load metrics from resolver instance %s: attempted to read missing statistic %s",
                    str(kid),
                    str(e),
                )

            yield self._create_resolver_metrics_loaded_gauge(kid, success)

    def describe(self) -> List[Metric]:
        # this function prevents the collector registry from invoking the collect function on startup
        return []

    def _parse_resolver_metrics(self, instance_id: KresID, metrics: Any) -> Generator[Metric, None, None]:
        sid = str(instance_id)

        # response latency histogram
        BUCKET_NAMES_IN_RESOLVER = ("1ms", "10ms", "50ms", "100ms", "250ms", "500ms", "1000ms", "1500ms", "slow")
        BUCKET_NAMES_PROMETHEUS = ("0.001", "0.01", "0.05", "0.1", "0.25", "0.5", "1.0", "1.5", "+Inf")
        yield _histogram(
            "resolver_response_latency",
            "Time it takes to respond to queries in seconds",
            label=("instance_id", sid),
            buckets=[
                (bnp, metrics[f"answer.{duration}"])
                for bnp, duration in zip(BUCKET_NAMES_PROMETHEUS, BUCKET_NAMES_IN_RESOLVER)
            ],
            sum_value=metrics["answer.sum_ms"] / 1_000,
        )

        yield _counter(
            "resolver_request_total",
            "total number of DNS requests (including internal client requests)",
            label=("instance_id", sid),
            value=metrics["request.total"],
        )
        yield _counter(
            "resolver_request_internal",
            "number of internal requests generated by Knot Resolver (e.g. DNSSEC trust anchor updates)",
            label=("instance_id", sid),
            value=metrics["request.internal"],
        )
        yield _counter(
            "resolver_request_udp",
            "number of external requests received over plain UDP (RFC 1035)",
            label=("instance_id", sid),
            value=metrics["request.udp"],
        )
        yield _counter(
            "resolver_request_tcp",
            "number of external requests received over plain TCP (RFC 1035)",
            label=("instance_id", sid),
            value=metrics["request.tcp"],
        )
        yield _counter(
            "resolver_request_dot",
            "number of external requests received over DNS-over-TLS (RFC 7858)",
            label=("instance_id", sid),
            value=metrics["request.dot"],
        )
        yield _counter(
            "resolver_request_doh",
            "number of external requests received over DNS-over-HTTP (RFC 8484)",
            label=("instance_id", sid),
            value=metrics["request.doh"],
        )
        yield _counter(
            "resolver_request_xdp",
            "number of external requests received over plain UDP via an AF_XDP socket",
            label=("instance_id", sid),
            value=metrics["request.xdp"],
        )
        yield _counter(
            "resolver_answer_total",
            "total number of answered queries",
            label=("instance_id", sid),
            value=metrics["answer.total"],
        )
        yield _counter(
            "resolver_answer_cached",
            "number of queries answered from cache",
            label=("instance_id", sid),
            value=metrics["answer.cached"],
        )
        yield _counter(
            "resolver_answer_rcode_noerror",
            "number of NOERROR answers",
            label=("instance_id", sid),
            value=metrics["answer.noerror"],
        )
        yield _counter(
            "resolver_answer_rcode_nodata",
            "number of NOERROR answers without any data",
            label=("instance_id", sid),
            value=metrics["answer.nodata"],
        )
        yield _counter(
            "resolver_answer_rcode_nxdomain",
            "number of NXDOMAIN answers",
            label=("instance_id", sid),
            value=metrics["answer.nxdomain"],
        )
        yield _counter(
            "resolver_answer_rcode_servfail",
            "number of SERVFAIL answers",
            label=("instance_id", sid),
            value=metrics["answer.servfail"],
        )
        yield _counter(
            "resolver_answer_flag_aa",
            "number of authoritative answers",
            label=("instance_id", sid),
            value=metrics["answer.aa"],
        )
        yield _counter(
            "resolver_answer_flag_tc",
            "number of truncated answers",
            label=("instance_id", sid),
            value=metrics["answer.tc"],
        )
        yield _counter(
            "resolver_answer_flag_ra",
            "number of answers with recursion available flag",
            label=("instance_id", sid),
            value=metrics["answer.ra"],
        )
        yield _counter(
            "resolver_answer_flags_rd",
            "number of recursion desired (in answer!)",
            label=("instance_id", sid),
            value=metrics["answer.rd"],
        )
        yield _counter(
            "resolver_answer_flag_ad",
            "number of authentic data (DNSSEC) answers",
            label=("instance_id", sid),
            value=metrics["answer.ad"],
        )
        yield _counter(
            "resolver_answer_flag_cd",
            "number of checking disabled (DNSSEC) answers",
            label=("instance_id", sid),
            value=metrics["answer.cd"],
        )
        yield _counter(
            "resolver_answer_flag_do",
            "number of DNSSEC answer OK",
            label=("instance_id", sid),
            value=metrics["answer.do"],
        )
        yield _counter(
            "resolver_answer_flag_edns0",
            "number of answers with EDNS0 present",
            label=("instance_id", sid),
            value=metrics["answer.edns0"],
        )
        yield _counter(
            "resolver_query_edns",
            "number of queries with EDNS present",
            label=("instance_id", sid),
            value=metrics["query.edns"],
        )
        yield _counter(
            "resolver_query_dnssec",
            "number of queries with DNSSEC DO=1",
            label=("instance_id", sid),
            value=metrics["query.dnssec"],
        )


_resolver_collector: Optional[ResolverCollector] = None


def unregister_resolver_metrics_for(subprocess: Subprocess) -> None:
    """
    Cancel metric collection from resolver subprocess
    """
    del _REGISTERED_RESOLVERS[subprocess.id]


def register_resolver_metrics_for(subprocess: Subprocess) -> None:
    """
    Register resolver subprocess for metric collection
    """
    _REGISTERED_RESOLVERS[subprocess.id] = subprocess


async def report_stats() -> bytes:
    """
    Collects metrics from everything, returns data string in Prometheus format.
    """

    # manually trigger stat collection so that we do not have to wait for it
    if _resolver_collector is not None:
        await _resolver_collector.collect_kresd_stats()
    else:
        raise RuntimeError("Function invoked before initializing the module!")

    # generate the report
    return exposition.generate_latest()  # type: ignore


async def _deny_turning_off_graphite_bridge(old_config: KresConfig, new_config: KresConfig) -> Result[None, str]:
    if old_config.monitoring.graphite is not None and new_config.monitoring.graphite is None:
        return Result.err(
            "You can't turn off graphite monitoring dynamically. If you really want this feature, please let the developers know."
        )

    if (
        old_config.monitoring.graphite is not None
        and new_config.monitoring.graphite is not None
        and old_config.monitoring.graphite != new_config.monitoring.graphite
    ):
        return Result.err("Changing graphite exporter configuration in runtime is not allowed.")

    return Result.ok(None)


_graphite_bridge: Optional[GraphiteBridge] = None


@only_on_real_changes(lambda c: c.monitoring.graphite)
async def _configure_graphite_bridge(config: KresConfig) -> None:
    """
    Starts graphite bridge if required
    """
    global _graphite_bridge
    if config.monitoring.graphite is not False and _graphite_bridge is None:
        logger.info(
            "Starting Graphite metrics exporter for [%s]:%d",
            config.monitoring.graphite.host,
            config.monitoring.graphite.port,
        )
        _graphite_bridge = GraphiteBridge((config.monitoring.graphite.host, config.monitoring.graphite.port))
        _graphite_bridge.start(  # type: ignore
            interval=config.monitoring.graphite.interval_sec.seconds(), prefix=config.monitoring.graphite.prefix
        )


async def init_monitoring(config_store: ConfigStore) -> None:
    """
    Initialize monitoring. Must be called before any other function from this module.
    """
    # register metrics collector
    global _resolver_collector
    _resolver_collector = ResolverCollector(config_store)
    REGISTRY.register(_resolver_collector)  # type: ignore

    # register graphite bridge
    await config_store.register_verifier(_deny_turning_off_graphite_bridge)
    await config_store.register_on_change_callback(_configure_graphite_bridge)
