import asyncio
import logging
from typing import TYPE_CHECKING, Dict, List, Tuple

if TYPE_CHECKING:
    from knot_resolver_manager.kresd_controller.interface import KresID, Subprocess


logger = logging.getLogger(__name__)


_REGISTERED_WORKERS: "Dict[KresID, Subprocess]" = {}


def get_registered_workers_kids() -> "List[KresID]":
    return list(_REGISTERED_WORKERS.keys())


async def command_single_registered_worker(cmd: str) -> "Tuple[KresID, str]":
    for sub in _REGISTERED_WORKERS.values():
        return sub.id, await sub.command(cmd)
    raise SubprocessControllerException(
        "Unable to execute the command. There is no kresd worker running to execute the command."
        "Try start/restart the resolver.",
    )


async def command_registered_workers(cmd: str) -> "Dict[KresID, str]":
    async def single_pair(sub: "Subprocess") -> "Tuple[KresID, str]":
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
