from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import TYPE_CHECKING

from knot_resolver.controller.subprocess import SubprocessType

if TYPE_CHECKING:
    from knot_resolver.controller.subprocess import Subprocess, SubprocessID


from .exceptions import KresManagerBaseError

logger = logging.getLogger(__name__)


_WORKERS: dict[SubprocessID, Subprocess] = {}


async def _command_worker(subprocess: Subprocess, command: str) -> object:
    if subprocess.type is not SubprocessType.WORKER:
        msg = (
            f"Cannot send a command via a Unix socket to a subprocess of type "
            f"{subprocess.type.value.capitalize()}; only WORKER subprocesses are supported."
        )
        raise RuntimeError(msg)

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter | None = None

    try:
        control_socket = f"./control/{subprocess.id.subprocess_num}"
        reader, writer = await asyncio.open_unix_connection(control_socket)

        # drop prompt and switch to JSON mode
        _ = await reader.read(2)
        writer.write(b"__json\n")

        writer.write(command.encode("utf8"))
        writer.write(b"\n")
        await writer.drain()

        (msg_len,) = struct.unpack(">I", await reader.read(4))
        result_bytes = await reader.readexactly(msg_len)

        try:
            return json.loads(result_bytes.decode("utf8"))
        except json.JSONDecodeError:
            return result_bytes.decode("utf8")

    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()


def get_workers_subprocesses_ids() -> list[SubprocessID]:
    return list(_WORKERS.keys())


async def command_worker(command: str) -> tuple[SubprocessID, object]:
    for worker in _WORKERS.values():
        return worker.id, await _command_worker(worker, command)

    msg = (
        "Unable to execute the command. There is no worker running to execute the command."
        "Try start/restart the resolver."
    )
    raise KresManagerBaseError(msg)


async def command_workers(command: str) -> dict[SubprocessID, object]:
    workers_results = await asyncio.gather(
        *(_command_worker(worker, command) for worker in _WORKERS.values())
    )
    return dict(zip(_WORKERS.keys(), workers_results))


def register_worker(subprocess: Subprocess) -> None:
    _WORKERS[subprocess.id] = subprocess


def unregister_worker(subprocess: Subprocess) -> None:
    del _WORKERS[subprocess.id]
