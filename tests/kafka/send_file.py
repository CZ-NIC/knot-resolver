
import socket
import sys
from pathlib import Path

from kafka import KafkaProducer  # type: ignore[import-untyped]
from kafka.errors import KafkaError  # type: ignore[import-untyped]

config_extensions = (".json", ".yaml", ".yml")

# args: send_file.py SERVER TOPIC FILE_PATH
server = sys.argv[1]
topic_name = sys.argv[2]
group_id = sys.argv[3]
file_path = Path(sys.argv[4])

file_name = file_path.name
extension = file_path.suffix

headers = [
    ("hostname", socket.gethostname().encode("utf-8")),
    ("file-name", file_name.encode("utf-8")),
]

# create kafka producer
producer = KafkaProducer(bootstrap_servers=[server])

def send_rpz_file(file_path: Path) -> None:
    with open(file_path, "r") as file:
        data_bytes = file.read().encode("utf-8")

    chunk_size = 1024 * 512
    total_chunks = (len(data_bytes) + chunk_size - 1) // chunk_size

    for chunk_index in range(total_chunks):
        offset = chunk_index * chunk_size
        chunk = data_bytes[offset : offset + chunk_size]

        chunk_headers = headers + [
            ("chunk-index", str(chunk_index + 1).encode("utf-8")),
            ("total-chunks", str(total_chunks).encode("utf-8")),
        ]

        try:
            future = producer.send(
                topic=topic_name,
                key=group_id,
                value=chunk,
                headers=chunk_headers
            )
            metadata = future.get(timeout=10)
            print(f"Successfully send chunk {chunk_index+1}/{total_chunks} of file '{file_path}' via kafka:"
            f"\n topic={metadata.topic} partition={metadata.partition} offset={metadata.offset}")

        except KafkaError as e:
            print(f"Failed to send chunk {chunk_index+1}/{total_chunks} of file '{file_path}': {e}")

def send_config_file(file_path: Path) -> None:
    with open(file_path, "r") as file:
        value = file.read().encode("utf-8")

    try:
        future = producer.send(
            topic=topic_name,
            key=file_name.encode("utf-8"),
            value=value,
            headers=headers
        )

        metadata = future.get(timeout=10)
        print(f"Successfully send file '{file_path}' via kafka:"
        f"\n topic={metadata.topic} partition={metadata.partition} offset={metadata.offset}")

    except KafkaError as e:
        print(f"Failed to send file '{file_path}': {e}")

if extension in config_extensions:
    send_config_file(file_path)
else:
    send_rpz_file(file_path)
