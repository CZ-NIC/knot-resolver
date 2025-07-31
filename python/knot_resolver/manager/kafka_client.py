import logging
import os
import shutil
from pathlib import Path
from threading import Timer
from typing import Any, Dict, List, Optional

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore, only_on_real_changes_update
from knot_resolver.manager.triggers import trigger_reload, trigger_renew
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling.parsing import parse_json

logger = logging.getLogger(__name__)


def kafka_config(config: KresConfig) -> List[Any]:
    return [
        config.hostname,
        config.kafka,
    ]


if KAFKA_LIB:
    from kafka import KafkaConsumer  # type: ignore[import-untyped,import-not-found]
    from kafka.consumer.fetcher import ConsumerRecord  # type: ignore[import-untyped,import-not-found]
    from kafka.errors import NoBrokersAvailable  # type: ignore[import-untyped,import-not-found]
    from kafka.structs import TopicPartition  # type: ignore[import-untyped,import-not-found]

    _kafka: Optional["KresKafkaClient"] = None

    class MessageHeaders:
        def __init__(self, headers: Dict[str, bytes]) -> None:
            self.hostname = headers["hostname"].decode("utf-8") if "hostname" in headers else None
            self.file_name = headers["file-name"].decode("utf-8") if "file-name" in headers else None
            self.total_chunks = int(headers["total-chunks"].decode("utf-8")) if "total-chunks" in headers else None
            self.chunk_index = int(headers["chunk-index"].decode("utf-8")) if "chunk-index" in headers else None

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

        def _consume(self) -> None:  # noqa: PLR0912, PLR0915
            if not self._consumer:
                return

            logger.info("Consuming messages...")
            messages: Dict[TopicPartition, List[ConsumerRecord]] = self._consumer.poll()

            for _partition, records in messages.items():
                for record in records:
                    try:
                        key: str = record.key.decode("utf-8")
                        value: str = record.value.decode("utf-8")
                        logger.info(f"Received message with '{key}' key")

                        # parse headers
                        headers = MessageHeaders(dict(record.headers))

                        my_hostname = str(self._config.hostname)
                        if headers.hostname != my_hostname:
                            logger.info(
                                f"Dropping message intended for '{headers.hostname}' hostname, this resolver hostname is '{my_hostname}'"
                            )
                            continue

                        # prepare files names
                        file_name = headers.file_name if headers.file_name else key
                        file_path = Path(file_name)
                        if not file_path.is_absolute():
                            file_path = self._config.kafka.files_dir.to_path() / file_path
                        file_path_tmp = f"{file_path}.tmp"
                        file_path_backup = f"{file_path}.backup"

                        _, file_extension = os.path.splitext(file_name)

                        # received full data in one message
                        # or last chunk of data
                        if headers.chunk_index == headers.total_chunks:
                            if file_path.exists():
                                shutil.copy(file_path, file_path_backup)
                                logger.debug(f"Created backup of '{file_path_backup}' file")

                            # rewrite only on first part, else append
                            mode = (
                                "w"
                                if (headers.chunk_index and int(headers.chunk_index)) or not headers.total_chunks == 1
                                else "a"
                            )
                            with open(file_path_tmp, mode) as file:
                                file.write(value)

                            config_extensions = (".json", ".yaml", ".yml")
                            if file_extension in config_extensions:
                                # validate config
                                KresConfig(parse_json(value))

                            os.replace(file_path_tmp, file_path)
                            logger.info(f"Saved data to '{file_path}'")

                            # config files must be reloaded
                            if file_extension in config_extensions:
                                # trigger delayed configuration reload
                                trigger_reload(self._config)
                            else:
                                # trigger delayed configuration renew
                                trigger_renew(self._config)
                        # received part of data
                        else:
                            # rewrite only on first part, else append
                            mode = "w" if headers.chunk_index and int(headers.chunk_index) == 1 else "a"
                            with open(file_path_tmp, mode) as file:
                                file.write(value)
                            logger.debug(f"Saved part {headers.chunk_index} of data to '{file_path_tmp}' file")
                    except Exception as e:
                        logger.error(f"Processing message failed with error: \n{e}")
                        continue

            # start new timer
            self._consumer_timer = Timer(5, self._consume)
            self._consumer_timer.start()

        def _consumer_connect(self) -> None:
            kafka = self._config.kafka

            kafka_logger = logging.getLogger("kafka")
            kafka_logger.setLevel(logging.ERROR)

            brokers = []
            for server in kafka.server.to_std():
                broker = str(server)
                brokers.append(broker.replace("@", ":") if server.port else f"{broker}:9092")

            logger.info("Connecting to Kafka brokers...")
            try:
                consumer = KafkaConsumer(
                    str(kafka.topic),
                    bootstrap_servers=brokers,
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


@only_on_real_changes_update(kafka_config)
async def _init_kafka_client(config: KresConfig) -> None:
    if KAFKA_LIB and config.kafka.enable:
        global _kafka
        if _kafka:
            _kafka.deinit()
        logger.info("Initializing Kafka client")
        _kafka = KresKafkaClient(config)


async def _deny_kafka_change(old_config: KresConfig, new_config: KresConfig) -> Result[None, str]:
    if old_config.kafka != new_config.kafka:
        return Result.err("Changing 'kafka' configuration is not allowed at runtime.")
    return Result.ok(None)


async def init_kafka_client(config_store: ConfigStore) -> None:
    await config_store.register_on_change_callback(_init_kafka_client)
    await config_store.register_verifier(_deny_kafka_change)


def deinit_kafka_client() -> None:
    if KAFKA_LIB:
        global _kafka  # noqa: PLW0602
        if _kafka:
            logger.info("Deinitializing Kafka client")
            _kafka.deinit()
