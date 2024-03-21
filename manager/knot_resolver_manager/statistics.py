import asyncio
import logging
from typing import TYPE_CHECKING, Dict, Optional

from knot_resolver_manager import compat
from knot_resolver_manager.config_store import ConfigStore
from knot_resolver_manager.kresd_controller.registered_workers import (
    command_registered_workers,
    get_registered_workers_kresids,
)
from knot_resolver_manager.utils.modeling.parsing import DataFormat

try:
    import prometheus_client  # type: ignore[import-not-found]
except ImportError:
    prometheus_client = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from knot_resolver_manager.kresd_controller.interface import KresID


logger = logging.getLogger(__name__)


def prometheus_support() -> bool:
    return prometheus_client is not None


class ResolverCollector:
    def __init__(self, config_store: ConfigStore) -> None:
        self._stats_raw: "Optional[Dict[KresID, object]]" = None
        self._config_store: ConfigStore = config_store
        self._collection_task: "Optional[asyncio.Task[None]]" = None
        self._skip_immediate_collection: bool = False

    def report_json(self) -> str:
        # schedule new stats collection
        self._trigger_stats_collection()

        # if we have no data, return metrics with information about it and exit
        if self._stats_raw is None:
            no_stats_dict: Dict[str, None] = {}
            for kresid in get_registered_workers_kresids():
                no_stats_dict[str(kresid)] = None
            return DataFormat.JSON.dict_dump(no_stats_dict)

        stats_dict: Dict[str, object] = {}
        for kresid, stats in self._stats_raw.items():
            stats_dict[str(kresid)] = stats

        return DataFormat.JSON.dict_dump(stats_dict)

    def report_prometheus(self) -> str:
        # schedule new stats collection
        self._trigger_stats_collection()

        return ""

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
        stats_raw = await command_registered_workers(cmd)
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

        if compat.asyncio.is_event_loop_running():
            # when running, we can schedule the new data collection
            if self._collection_task is not None and not self._collection_task.done():
                logger.warning("Statistics collection task is still running. Skipping scheduling of a new one!")
            else:
                self._collection_task = compat.asyncio.create_task(
                    self.collect_kresd_stats(_triggered_from_prometheus_library=True)
                )

        else:
            # when not running, we can start a new loop (we are not in the manager's main thread)
            compat.asyncio.run(self.collect_kresd_stats(_triggered_from_prometheus_library=True))


_resolver_collector: Optional[ResolverCollector] = None


async def report_stats_json() -> bytes:
    """
    Collects metrics from everything, returns data string in JSON format.
    """

    # manually trigger stat collection so that we do not have to wait for it
    if _resolver_collector is not None:
        await _resolver_collector.collect_kresd_stats()
    else:
        raise RuntimeError("Function invoked before initializing the module!")

    return _resolver_collector.report_json().encode()


async def report_stats_prometheus() -> bytes:
    """
    Collects metrics from everything, returns data string in Prometheus format.
    """

    # manually trigger stat collection so that we do not have to wait for it
    if _resolver_collector is not None:
        await _resolver_collector.collect_kresd_stats()
    else:
        raise RuntimeError("Function invoked before initializing the module!")

    return _resolver_collector.report_prometheus().encode()


async def init_monitoring(config_store: ConfigStore) -> None:
    """
    Initialize monitoring. Must be called before any other function from this module.
    """
    # register metrics collector
    global _resolver_collector
    _resolver_collector = ResolverCollector(config_store)
