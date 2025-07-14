import logging
from threading import Timer
from typing import Dict, List, Optional

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling import parse_json

logger = logging.getLogger(__name__)


if KAFKA_LIB:
    from kafka import KafkaConsumer  # type: ignore[import-untyped]
    from kafka.consumer.fetcher import ConsumerRecord  # type: ignore[import-untyped]
    from kafka.errors import NoBrokersAvailable  # type: ignore[import-untyped]
    from kafka.structs import TopicPartition  # type: ignore[import-untyped]

    _kafka: Optional["KresKafkaClient"] = None

    class KresKafkaClient:
        def __init__(self, config: KresConfig) -> None:
            self._config = config
            self._files: Dict[str, str] = {}

            self._consumer: Optional[KafkaConsumer] = None
            self._consumer_timer: Optional[Timer] = None
            self._consumer_connect()
            self._consume()

        def deinit(self) -> None:
            if self._consumer_timer:
                self._consumer_timer.cancel()
            if self._consumer:
                self._consumer.close()

        def _consume(self) -> None:
            if not self._consumer:
                return

            logger.info("Consuming...")
            messages: Dict[TopicPartition, List[ConsumerRecord]] = self._consumer.poll()

            for _partition, records in messages.items():
                for record in records:
                    try:
                        key: str = record.key.decode("utf-8")
                        value: str = record.value.decode("utf-8")

                        logger.info(f"Received message with '{key}' key")

                        # configuration
                        if key == "config":
                            _new_config = parse_json(value)
                            logger.info("Configuration applied")
                        # start of a file
                        elif key[-2] == ":" and key[-1].isdigit():
                            file_name = key[:-2]
                            if file_name in self._files:
                                self._files[file_name] += value
                            else:
                                self._files[file_name] = value
                            logger.info(f"Received s part of data for '{file_name}' file")
                        # end of a file
                        elif key.endswith(":END"):
                            file_name = key[:-4]
                            with open(file_name, "w") as file:
                                file.write(self._files[file_name])
                            del self._files[file_name]
                            logger.info(f"Saved data to '{file_name}'")
                    except Exception as e:
                        logger.error(f"Processing message failed with error: {e}")
                        continue

            self._consumer_timer = Timer(5, self._consume)
            self._consumer_timer.start()

        def _consumer_connect(self) -> None:
            kafka = self._config.kafka
            broker = f"{kafka.server.addr}:{kafka.server.port if kafka.server.port else 9092}"

            logger.info("Connecting to Kafka broker...")
            try:
                consumer = KafkaConsumer(
                    str(kafka.topic),
                    bootstrap_servers=broker,
                    client_id=str(self._config.hostname),
                )
                self._consumer = consumer
                logger.info("Successfully connected to Kafka broker")
            except NoBrokersAvailable:
                logger.error(f"Connecting to Kafka broker '{kafka.server}' has failed: no broker available")
                self._consumer = None


async def _deny_kafka_change(old_config: KresConfig, new_config: KresConfig) -> Result[None, str]:
    if old_config.kafka != new_config.kafka:
        return Result.err("Changing 'kafka' configuration is not allowed at runtime.")
    return Result.ok(None)


async def init_kafka_client(config_store: ConfigStore) -> None:
    config = config_store.get()

    if config.kafka.enable and KAFKA_LIB:
        logger.info("Initializing Kafka client")
        global _kafka
        _kafka = KresKafkaClient(config)
        await config_store.register_verifier(_deny_kafka_change)


def deinit_kafka_client() -> None:
    if KAFKA_LIB:
        global _kafka  # noqa: PLW0602
        if _kafka:
            logger.info("Deinitializing Kafka client")
            _kafka.deinit()
