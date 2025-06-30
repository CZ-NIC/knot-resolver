import logging
from typing import Optional

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.utils.functional import Result

logger = logging.getLogger(__name__)


if KAFKA_LIB:
    from kafka import KafkaConsumer  # type: ignore[import-untyped]
    from kafka.errors import NoBrokersAvailable  # type: ignore[import-untyped]

    _kafka: Optional["KresKafkaClient"] = None

    class KresKafkaClient:
        def __init__(self, config_store: ConfigStore) -> None:
            self._config_store = config_store
            config = config_store.get()

            topic = "test"
            server = "127.0.0.1:9092"

            try:
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=server,
                    client_id=str(config.hostname),
                )
            except NoBrokersAvailable:
                logger.error(f"Connecting to Kafka server '{server}' has failed: no broker available")

            self._consumer = consumer
            logger.info("Successfully connected to Kafka server")


async def _deny_kafka_change(old_config: KresConfig, new_config: KresConfig) -> Result[None, str]:
    return Result.ok(None)


async def init_kafka_client(config_store: ConfigStore) -> None:
    if KAFKA_LIB:
        logger.info("Initializing Kafka client")
        global _kafka
        _kafka = KresKafkaClient(config_store)

        await config_store.register_verifier(_deny_kafka_change)
