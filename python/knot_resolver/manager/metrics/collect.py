import logging
from typing import Dict, Optional

from knot_resolver.controller.interface import KresID
from knot_resolver.controller.registered_workers import command_registered_workers, get_registered_workers_kresids
from knot_resolver.datamodel import KresConfig
from knot_resolver.utils.modeling.parsing import DataFormat

logger = logging.getLogger(__name__)


async def collect_kresd_workers_metrics(config: KresConfig) -> Optional[Dict[KresID, object]]:
    if config.monitoring.metrics == "manager-only":
        logger.debug("Skipping kresd stat collection due to configuration")
        return None

    cmd = "collect_statistics()"
    if config.monitoring.metrics == "lazy":
        cmd = "collect_lazy_statistics()"
    logger.debug(f"Collecting stats from all kresd workers using method '{cmd}'")

    return await command_registered_workers(cmd)


async def report_json(config: KresConfig) -> bytes:
    metrics_raw = await collect_kresd_workers_metrics(config)
    metrics_dict: Dict[str, Optional[object]] = {}

    if metrics_raw:
        for kresd_id, kresd_metrics in metrics_raw.items():
            metrics_dict[str(kresd_id)] = kresd_metrics
    else:
        # if we have no metrics, return None for every kresd worker
        for kresd_id in get_registered_workers_kresids():
            metrics_dict[str(kresd_id)] = None

    return DataFormat.JSON.dict_dump(metrics_dict).encode()
