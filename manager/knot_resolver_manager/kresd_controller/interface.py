from enum import Enum, auto
from typing import Iterable

from knot_resolver_manager.kres_id import KresID


class SubprocessType(Enum):
    KRESD = auto()
    GC = auto()


class Subprocess:
    """
    One SubprocessInstance corresponds to one manager's subprocess
    """

    @property
    def type(self) -> SubprocessType:
        raise NotImplementedError()

    @property
    def id(self) -> str:
        raise NotImplementedError()

    async def is_running(self) -> bool:
        raise NotImplementedError()

    async def start(self) -> None:
        raise NotImplementedError()

    async def stop(self) -> None:
        raise NotImplementedError()

    async def restart(self) -> None:
        raise NotImplementedError()

    def __eq__(self, o: object) -> bool:
        return isinstance(o, type(self)) and o.type == self.type and o.id == self.id

    def __hash__(self) -> int:
        return hash(type(self)) ^ hash(self.type) ^ hash(self.id)


class SubprocessController:
    """
    The common Subprocess Controller interface. This is what KresManager requires and what has to be implemented by all
    controllers.
    """

    async def is_controller_available(self) -> bool:
        raise NotImplementedError()

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        raise NotImplementedError()

    async def initialize_controller(self) -> None:
        """
        Should be called when we want to really start using the controller.
        """
        raise NotImplementedError()

    async def shutdown_controller(self) -> None:
        """
        Called when the manager is gracefully shutting down. Allows us to stop
        the service manager process or simply cleanup, so that we don't reuse
        the same resources in a new run.
        """
        raise NotImplementedError()

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: KresID) -> Subprocess:
        """
        Return a Subprocess object which can be operated on. The subprocess is not
        started or in any way active after this call. That has to be performaed manually
        using the returned object itself.

        Must NOT be called before initialize_controller()
        """
        raise NotImplementedError()
