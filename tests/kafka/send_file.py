
import socket
import sys
import time
from pathlib import Path

from kafka import KafkaProducer  # type: ignore[import-untyped]
from kafka.errors import KafkaError  # type: ignore[import-untyped]

config_extensions = (".json", ".yaml", ".yml")

# args: send_file.py SERVER TOPIC FILE_PATH
server = sys.argv[1]
topic_name = sys.argv[2]
file_path = Path(sys.argv[3])

# if file_path is directory
files_paths = [file_path]
if file_path.is_dir():
    files_paths = [p for p in file_path.iterdir() if p.is_file()]
files_paths.sort()

file_name = file_path.name
extension = file_path.suffix
total_chunks = len(files_paths)

# create kafka producer
producer = KafkaProducer(bootstrap_servers=[server])

def send_file(file_path: Path, chunk_index: int) -> None:

    headers = [
        ("hostname", socket.gethostname().encode("utf-8")),
    ]
    if extension not in config_extensions:
        headers.append(("file-name", file_name.encode("utf-8")))
    if extension not in config_extensions:
        headers.append(("total-chunks", f"{total_chunks}".encode("utf-8")))
    if extension not in config_extensions:
        headers.append(("chunk-index", f"{chunk_index}".encode("utf-8")))

    with open(file_path, "r") as file:
        value = file.read().encode("utf-8")

    try:
        producer.send(
            topic=topic_name,
            key=file_name.encode("utf-8"),
            value=value,
            headers=headers
        )
        print(f"Successfully send file '{file_path}' via kafka")
    except KafkaError as e:
        print(f"Failed to send file '{file_path}': {e}")

for i in range(0, total_chunks):
    send_file(files_paths[i], i+1)
    time.sleep(1)
