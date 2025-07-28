import logging
import os
import shutil
from pathlib import Path
from threading import Timer
from typing import Dict, List, Optional
from urllib.parse import quote

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.manager.triggers import trigger_renew
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling.parsing import DataFormat, data_combine, parse_json
from knot_resolver.utils.requests import SocketDesc, request

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

        def _consume(self) -> None:  # noqa: PLR0915
            if not self._consumer:
                return

            logger.info("Consuming...")
            messages: Dict[TopicPartition, List[ConsumerRecord]] = self._consumer.poll()

            for _partition, records in messages.items():
                for record in records:
                    try:
                        key: str = record.key.decode("utf-8")
                        value: str = record.value.decode("utf-8")

                        # messages without key
                        # config
                        if not key:
                            config_orig = self._config.get_unparsed_data()
                            parsed = parse_json(value)
                            config_new = data_combine(config_orig, parsed)

                            file_path = self._config.kafka.files_dir.to_path() / "config.kafka.json"
                            file_path_tmp = f"{file_path}.tmp"
                            file_path_backup = f"{file_path}.backup"
                            shutil.copy(file_path, file_path_backup)
                            with open(file_path_tmp, "w") as file:
                                file.write(value)

                            management = self._config.management
                            socket = SocketDesc(
                                f'http+unix://{quote(str(management.unix_socket), safe="")}/',
                                'Key "/management/unix-socket" in validated configuration',
                            )
                            if management.interface:
                                socket = SocketDesc(
                                    f"http://{management.interface.addr}:{management.interface.port}",
                                    'Key "/management/interface" in validated configuration',
                                )

                            body = DataFormat.JSON.dict_dump(config_new)
                            response = request(socket, "PUT", "v1/config", body)

                            if response.status != 200:
                                logger.error(f"Failed to apply new config:\n{response.body}")
                                continue
                            os.replace(file_path_tmp, file_path)
                            continue

                        # messages with key
                        # RPZ or other files

                        logger.info(f"Received message with '{key}' key")
                        key_split = key.split(":")

                        # prepare files names
                        file_name = key_split[0]
                        file_path = Path(file_name)
                        if not file_path.is_absolute():
                            file_path = self._config.kafka.files_dir.to_path() / file_name

                        file_path_tmp = f"{file_path}.tmp"
                        file_path_backup = f"{file_path}.backup"

                        file_part = key_split[1] if len(key_split) > 1 else None
                        _, file_extension = os.path.splitext(file_name)

                        # received part of data
                        if file_part and file_part.isdigit():
                            # rewrite only on first part, else append
                            mode = "w" if int(file_part) == 0 else "a"
                            with open(file_path_tmp, mode) as file:
                                file.write(value)
                            logger.debug(f"Saved part {file_part} of data to '{file_path_tmp}' file")
                        # received END of data
                        elif file_part and file_part == "END":
                            shutil.copy(file_path, file_path_backup)
                            logger.debug(f"Created backup of '{file_path_backup}' file")

                            os.replace(file_path, file_path_tmp)
                            logger.info(f"Saved data to '{file_path}'")

                            # trigger delayed configuration renew
                            trigger_renew(self._config)
                        else:
                            logger.error("Failed to parse message key")
                    except Exception as e:
                        logger.error(f"Processing message failed with error: \n{e}")
                        continue

            self._consumer_timer = Timer(5, self._consume)
            self._consumer_timer.start()

        def _consumer_connect(self) -> None:
            kafka = self._config.kafka

            brokers = []
            for server in kafka.server.to_std():
                broker = str(server)
                brokers.append(broker.replace("@", ":") if server.port else f"{broker}:9092")

            kafka_logger = logging.getLogger("kafka")
            kafka_logger.setLevel(logging.WARN)

            logger.info("Connecting to Kafka broker...")
            try:
                consumer = KafkaConsumer(
                    str(kafka.topic),
                    bootstrap_servers=brokers,
                    # client_id=str(self._config.hostname),
                    # security_protocol=str(kafka.security_protocol).upper(),
                    # ssl_cafile=str(kafka.ca_file) if kafka.ca_file else None,
                    # ssl_certfile=str(kafka.cert_file) if kafka.cert_file else None,
                    # ssl_keyfile=str(kafka.key_file) if kafka.key_file else None,
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
