import logging
import os
import shutil
from threading import Timer
from typing import Dict, List, Optional

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.manager.triggers import trigger_reload
from knot_resolver.utils.functional import Result

logger = logging.getLogger(__name__)


if KAFKA_LIB:
    from kafka import KafkaConsumer  # type: ignore[import-untyped,import-not-found]
    from kafka.consumer.fetcher import ConsumerRecord  # type: ignore[import-untyped,import-not-found]
    from kafka.errors import NoBrokersAvailable  # type: ignore[import-untyped,import-not-found]
    from kafka.structs import TopicPartition  # type: ignore[import-untyped,import-not-found]

    _kafka: Optional["KresKafkaClient"] = None

    class KresKafkaClient:
        def __init__(self, config: KresConfig) -> None:
            self._config = config

            self._consumer: Optional[KafkaConsumer] = None
            self._consumer_connect()
            self._consumer_timer = Timer(5, self._consume)
            self._consumer_timer.start()

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
                        key_split = key.split(":")
                        value: str = record.value.decode("utf-8")

                        logger.info(f"Received message with '{key}' key")

                        # prepare files names
                        file_name = key_split[0]
                        file_name_tmp = f"{file_name}.tmp"
                        file_name_backup = f"{file_name}.backup"

                        file_part = key_split[1] if len(key_split) > 1 else None
                        _, file_extension = os.path.splitext(file_name)

                        # received part of data
                        if file_part and file_part.isdigit():
                            # rewrite only on first part, else append
                            mode = "w" if int(file_part) == 0 else "a"
                            with open(file_name_tmp, mode) as file:
                                file.write(value)
                            logger.debug(f"Saved part {file_part} of data to '{file_name_tmp}' file")
                        # received END of data
                        elif file_part and file_part == "END":
                            shutil.copy(file_name, file_name_backup)
                            logger.debug(f"Created backup of '{file_name_backup}' file")

                            os.replace(file_name, file_name_tmp)
                            logger.info(f"Saved data to '{file_name}'")

                            # trigger delayed configuration reload
                            trigger_reload(self._config)
                        else:
                            logger.error("Failed to parse message key")
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
                    security_protocol=str(kafka.security_protocol).upper(),
                    ssl_cafile=str(kafka.ca_file) if kafka.ca_file else None,
                    ssl_certfile=str(kafka.cert_file) if kafka.cert_file else None,
                    ssl_keyfile=str(kafka.key_file) if kafka.key_file else None,
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
