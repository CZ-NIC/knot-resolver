import asyncio
import logging
from typing import TYPE_CHECKING, Dict, List, Tuple

from .exceptions import SubprocessControllerError

if TYPE_CHECKING:
    from knot_resolver.controller.interface import KresID, Subprocess


logger = logging.getLogger(__name__)


_REGISTERED_WORKERS: "Dict[KresID, Subprocess]" = {}


def get_registered_workers_kresids() -> "List[KresID]":
    return list(_REGISTERED_WORKERS.keys())


async def command_single_registered_worker(cmd: str) -> "Tuple[KresID, object]":
    for sub in _REGISTERED_WORKERS.values():
        return sub.id, await sub.command(cmd)
    raise SubprocessControllerError(
        "Unable to execute the command. There is no kresd worker running to execute the command."
        "Try start/restart the resolver.",
    )


async def command_registered_workers(cmd: str) -> "Dict[KresID, object]":
    async def single_pair(sub: "Subprocess") -> "Tuple[KresID, object]":
        return sub.id, await sub.command(cmd)

    pairs = await asyncio.gather(*(single_pair(inst) for inst in _REGISTERED_WORKERS.values()))
    return dict(pairs)


def unregister_worker(subprocess: "Subprocess") -> None:
    """
    Unregister kresd worker "Subprocess" from the list.
    """
    del _REGISTERED_WORKERS[subprocess.id]


def register_worker(subprocess: "Subprocess") -> None:
    """
    Register kresd worker "Subprocess" on the list.
    """
    _REGISTERED_WORKERS[subprocess.id] = subprocess
