import asyncio
from typing import Iterable, Optional
from uuid import uuid4


class BaseKresdController:
    """
    The common Kresd Controller interface. This is what KresManager requires and what has to be implemented by all
    controllers.
    """

    def __init__(self, kresd_id: Optional[str] = None):
        self._lock = asyncio.Lock()
        self.id: str = kresd_id or str(uuid4())

    @staticmethod
    async def is_controller_available() -> bool:
        raise NotImplementedError()

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def start(self) -> None:
        raise NotImplementedError()

    async def stop(self) -> None:
        raise NotImplementedError()

    async def restart(self) -> None:
        raise NotImplementedError()

    @staticmethod
    async def get_all_running_instances() -> Iterable["BaseKresdController"]:
        raise NotImplementedError()
