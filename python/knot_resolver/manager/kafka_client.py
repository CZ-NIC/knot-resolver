import asyncio
import logging
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel import KresConfig
from knot_resolver.manager.config_store import ConfigStore
from knot_resolver.manager.exceptions import KresKafkaClientError
from knot_resolver.manager.triggers import trigger_reload
from knot_resolver.utils import compat
from knot_resolver.utils.functional import Result
from knot_resolver.utils.modeling import try_to_parse
from knot_resolver.utils.modeling.exceptions import DataParsingError, DataValidationError

logger = logging.getLogger(__name__)


def kafka_config(config: KresConfig) -> List[Any]:
    return [
        config.hostname,
        config.kafka,
    ]


if KAFKA_LIB:
    from kafka import KafkaConsumer  # type: ignore[import-untyped,import-not-found]
    from kafka.consumer.fetcher import ConsumerRecord  # type: ignore[import-untyped,import-not-found]
    from kafka.errors import KafkaError  # type: ignore[import-untyped,import-not-found]
    from kafka.structs import TopicPartition  # type: ignore[import-untyped,import-not-found]

    config_file_extensions = (".json", ".yaml", ".yml")
    binary_file_extensions = ".pt"

    _kafka: Optional["KresKafkaClient"] = None

    def backup_and_replace(file_src_path: Path, file_dest_path: Path) -> None:
        if file_dest_path.exists():
            file_backup_path = Path(f"{file_dest_path}.backup")
            shutil.copy(file_dest_path, file_backup_path)
            logger.debug(f"Created backup file '{file_backup_path}'")
        file_src_path.replace(file_dest_path)
        logger.info(f"Saved new data to '{file_dest_path}'")

    def create_file_chunk_path(file: Path, index: int) -> Path:
        return Path(f"{file}.chunks/{index}")

    def create_file_tmp_path(file: Path) -> Path:
        return Path(f"{file}.tmp")

    class Headers:
        def __init__(self, headers: List[Tuple[str, bytes]]) -> None:
            # default values
            self.hostname: Optional[str] = None
            self.file_name: Optional[str] = None
            self.total_chunks: Optional[int] = None
            self.chunk_index: Optional[int] = None
            # assign values from the message headers
            self._assign_headers(headers)

        def _assign_headers(self, headers: List[Tuple[str, bytes]]) -> None:
            for hkey, hvalue in headers:
                if hkey == "hostname":
                    self.hostname = hvalue.decode("utf-8")
                elif hkey == "file-name":
                    self.file_name = hvalue.decode("utf-8")
                elif hkey == "total-chunks":
                    self.total_chunks = int(hvalue)
                elif hkey == "chunk-index":
                    self.chunk_index = int(hvalue)
                else:
                    logger.warning(f"Unknown headers key '{hkey}'")

    def hostname_match(headers: Headers, hostname: str) -> bool:
        if not headers.hostname:
            KresKafkaClientError("The required 'hostname' message header is missing")

        # skip processing if hostname don't match
        if headers.hostname != hostname:
            logger.info(
                f"The resolver's hostname '{hostname}' do not match the message header hostname '{headers.hostname}':"
                " The message is intended for a resolver with the matching hostname"
            )
            return False
        return True

    def check_chunk_headers(headers: Headers) -> None:
        index = headers.chunk_index
        total = headers.total_chunks

        if index and not total:
            raise KresKafkaClientError("missing 'total-chunks' message header")
        if total and not index:
            raise KresKafkaClientError("missing 'chunk-index' message header")
        if index and total and index > total:
            raise KresKafkaClientError(
                f"'chunk-index' value cannot be bigger than 'total-chunks' value '{index} > {total}'"
            )

    def cleanup_files_dir(config_file_path: Path, files_dir: Path) -> None:
        config_file_backup_path = Path(f"{config_file_path}.backup")
        used_files: List[Path] = [config_file_path, config_file_backup_path]

        # current config
        with open(config_file_path, "r") as backup_file:
            current_config = KresConfig(try_to_parse(backup_file.read()))
        if current_config.tunnel_filter.file:
            used_files.append(current_config.tunnel_filter.file.to_path().resolve())
            used_files.append(Path(f"{current_config.tunnel_filter.file.to_path()}.backup").resolve())
        if current_config.local_data.rpz:
            for rpz in current_config.local_data.rpz:
                used_files.append(rpz.file.to_path().resolve())
                used_files.append(Path(f"{rpz.file.to_path()}.backup").resolve())

        # keep backup config functional
        if config_file_backup_path.exists():
            with open(config_file_backup_path, "r") as backup_file:
                backup_config = KresConfig(try_to_parse(backup_file.read()))
            if backup_config.tunnel_filter.file:
                used_files.append(backup_config.tunnel_filter.file.to_path().resolve())
                used_files.append(Path(f"{backup_config.tunnel_filter.file.to_path()}.backup").resolve())
            if backup_config.local_data.rpz:
                for backup_rpz in backup_config.local_data.rpz:
                    used_files.append(backup_rpz.file.to_path().resolve())
                    used_files.append(Path(f"{backup_rpz.file.to_path()}.backup").resolve())

        # delete unused files from current and backup config
        for path in files_dir.iterdir():
            if path.is_file() and path.resolve() not in used_files:
                logger.debug(f"Cleaned up file '{path}'")
                path.unlink()

    def process_record(config: KresConfig, record: ConsumerRecord) -> None:  # noqa: PLR0912, PLR0915
        key: str = record.key.decode("utf-8")
        value: bytes = record.value
        headers = Headers(record.headers)

        logger.info(f"Received message with '{key}' key (group-id)")

        hostname = str(config.hostname)
        group_id = config.kafka.group_id

        if not group_id and not headers.hostname:
            raise KresKafkaClientError(
                "The 'group-id' option is not configured and the 'hostname' message header is also missing:"
                " It is not possible to determine which resolver the message is intended for."
            )

        if headers.hostname and headers.hostname == hostname:
            logger.info("The message headers hostname matches the resolver's. The message will be processed.")
        elif group_id and key == str(group_id):
            logger.info("The message key (group-id) matches the resolver's. The message will be processed.")
        else:
            logger.info(
                f"The resolver's group-id '{str(group_id)}' or hostname '{hostname}'"
                f" do not match with the message key (group-id) '{key}' or headers hostname '{headers.hostname}':"
                " The message is intended for a resolver with the matching group-id or hostname."
                " Message processing is skipped."
            )
            return

        # check chunks
        check_chunk_headers(headers)

        # check file name
        if not headers.file_name:
            raise KresKafkaClientError("missing 'file-name' message header")

        # prepare file path and extension
        file_path = Path(headers.file_name)
        file_extension = file_path.suffix
        if not file_path.is_absolute():
            file_path = config.kafka.files_dir.to_path() / file_path
        file_tmp_path = create_file_tmp_path(file_path)

        index = headers.chunk_index
        total = headers.total_chunks
        file_is_ready = False

        # received complete data in one message
        if not index and not total or index == 1 and total == 1:
            with open(file_tmp_path, "wb") as file:
                file.write(value)
            logger.debug(f"Saved complete data to '{file_tmp_path}' file")
            file_is_ready = True

        # received chunk of data
        elif index and total:
            file_chunk_path = create_file_chunk_path(file_path, index)
            # create chunks dir if not exists
            file_chunk_path.parent.mkdir(exist_ok=True)
            with open(file_chunk_path, "wb") as file:
                file.write(value)
            logger.debug(f"Saved chunk {index} of data to '{file_chunk_path}' file")

            missing: List[int] = []
            file_chunks_paths: List[Path] = []
            for i in range(1, total + 1):
                path = create_file_chunk_path(file_path, i)
                if path.exists():
                    file_chunks_paths.append(path)
                else:
                    missing.append(i)

            if len(file_chunks_paths) == total:
                with open(file_tmp_path, "wb") as tmp_file:
                    for path in file_chunks_paths:
                        with open(path, "rb") as chunk_file:
                            tmp_file.write(chunk_file.read())
                logger.debug(f"Saved complete data from all chunks to '{file_tmp_path}' file")
                file_is_ready = True

                # remove chunks dir
                chunks_dir = f"{file_path}.chunks"
                shutil.rmtree(chunks_dir)
                logger.debug(f"Removed chunks directory '{chunks_dir}'")
            else:
                logger.debug(f"The file '{headers.file_name}' cannot be assembled yet: missing chunks {missing}")

        # complete tmp file is ready
        if file_tmp_path.exists() and file_is_ready:
            # configuration files (.yaml, .json, ...all)
            if file_extension in config_file_extensions:
                # validate configuration
                KresConfig(try_to_parse(value.decode("utf-8")))

                # backup and replace file with new data
                backup_and_replace(file_tmp_path, file_path)

                # cleanup old files
                cleanup_files_dir(file_path, config.kafka.files_dir.to_path())

                # trigger reload
                trigger_reload(config, force=True)

            # other files (.rpz, .pt, ...)
            else:
                # backup and replace file with new data
                backup_and_replace(file_tmp_path, file_path)

                # We don't need to renew the configuration
                # because the new JSON configuration should always follow the other files.
                # trigger_renew(config, force=True)

    logger.info("Successfully processed message")

    def process_messages(messages: Dict[TopicPartition, List[ConsumerRecord]], config: KresConfig) -> None:
        error_msg_prefix = "Processing message failed with"

        for _partition, records in messages.items():
            for record in records:
                try:
                    process_record(config, record)
                except KresKafkaClientError as e:
                    logger.error(f"{error_msg_prefix} Kafka client error:\n{e}")
                except DataParsingError as e:
                    logger.error(f"{error_msg_prefix} data parsing error:\n{e}")
                except DataValidationError as e:
                    logger.error(f"{error_msg_prefix} data validation error:\n{e}")
                except Exception as e:
                    logger.error(f"{error_msg_prefix} unknown error:\n{e}")

    class KresKafkaClient:
        def __init__(self, config: KresConfig) -> None:
            self._config = config
            self._consumer: Optional[KafkaConsumer] = None
            self._consumer_task: Optional["asyncio.Task[None]"] = None

            # reduce the verbosity of kafka module logger
            kafka_logger = logging.getLogger("kafka")
            # kafka_logger.setLevel(logging.ERROR)
            kafka_logger.propagate = False

            brokers = []
            for server in config.kafka.server.to_std():
                broker = str(server)
                brokers.append(broker.replace("@", ":") if server.port else f"{broker}:9092")
            self._brokers: List[str] = brokers

            if compat.asyncio.is_event_loop_running():
                self._consumer_task = compat.asyncio.create_task(self._consumer_run())
            else:
                self._consumer_task = compat.asyncio.run(self._consumer_run())

        def _consumer_connect(self) -> None:
            error_msg_prefix = f"Connecting consumer to Kafka broker(s) '{self._brokers}' has failed with"
            config_kafka = self._config.kafka

            # close old consumer connection
            if self._consumer:
                self._consumer.close()
                self._consumer = None

            logger.info("Connecting to Kafka broker(s)...")
            try:
                consumer = KafkaConsumer(
                    str(config_kafka.topic),
                    bootstrap_servers=self._brokers,
                    client_id=str(self._config.hostname),
                    group_id=str(config_kafka.group_id),
                    security_protocol=str(config_kafka.security_protocol).upper(),
                    ssl_cafile=str(config_kafka.ca_file) if config_kafka.ca_file else None,
                    ssl_certfile=str(config_kafka.cert_file) if config_kafka.cert_file else None,
                    ssl_keyfile=str(config_kafka.key_file) if config_kafka.key_file else None,
                )
                self._consumer = consumer
                logger.info("Successfully connected to Kafka broker")
            except KafkaError as e:
                logger.error(f"{error_msg_prefix} {e}")
            except Exception as e:
                logger.error(f"{error_msg_prefix} unknown error:\n{e}")

        def deinit(self) -> None:
            if self._consumer_task:
                self._consumer_task.cancel()
            if self._consumer:
                self._consumer.close()
                self._consumer = None

        async def _consumer_run(self) -> None:
            while True:
                if not self._consumer:
                    # connect to brokers
                    self._consumer_connect()
                else:
                    # ready to consume messages
                    error_msg_prefix = "Consuming messages failed with"
                    try:
                        logger.info("Started consuming messages...")
                        messages: Dict[TopicPartition, List[ConsumerRecord]] = self._consumer.poll(timeout_ms=100)
                        logger.debug(f"Successfully consumed {len(messages)} messages")
                        # ready to process messages
                        process_messages(messages, self._config)
                        if not messages:
                            await asyncio.sleep(10)
                    except KafkaError as e:
                        logger.error(f"{error_msg_prefix} Kafka error:\n{e}")
                        self._consumer_connect()
                    except Exception as e:
                        logger.error(f"{error_msg_prefix} unknown error:\n{e}")
                        self._consumer_connect()


async def _deny_kafka_change(old_config: KresConfig, new_config: KresConfig, _force: bool = False) -> Result[None, str]:
    if old_config.kafka != new_config.kafka:
        return Result.err("Changing 'kafka' configuration is not allowed at runtime.")
    return Result.ok(None)


async def init_kafka_client(config_store: ConfigStore) -> None:
    config = config_store.get()
    if KAFKA_LIB and config.kafka.enable:
        global _kafka
        if _kafka:
            _kafka.deinit()
        logger.info("Initializing Kafka client")
        _kafka = KresKafkaClient(config)
    # await config_store.register_on_change_callback(_init_kafka_client)
    await config_store.register_verifier(_deny_kafka_change)


def deinit_kafka_client() -> None:
    if KAFKA_LIB:
        global _kafka  # noqa: PLW0602
        if _kafka:
            logger.info("Deinitializing Kafka client")
            _kafka.deinit()
