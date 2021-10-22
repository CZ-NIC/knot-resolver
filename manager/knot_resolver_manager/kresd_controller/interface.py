from enum import Enum, auto
from typing import Dict, Iterable

from knot_resolver_manager.constants import kresd_config_file
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import SubprocessControllerException
from knot_resolver_manager.kres_id import KresID
from knot_resolver_manager.utils.async_utils import writefile


class SubprocessType(Enum):
    KRESD = auto()
    GC = auto()


class Subprocess:
    """
    One SubprocessInstance corresponds to one manager's subprocess
    """

    def __init__(self, config: KresConfig) -> None:
        self._config = config

    async def start(self) -> None:
        # create config file
        lua_config = self._config.render_lua()
        await writefile(kresd_config_file(self._config, self.id), lua_config)
        try:
            await self._start()
        except SubprocessControllerException as e:
            kresd_config_file(self._config, self.id).unlink()
            raise e

    async def apply_new_config(self, new_config: KresConfig) -> None:
        self._config = new_config
        # update config file
        lua_config = new_config.render_lua()
        await writefile(kresd_config_file(new_config, self.id), lua_config)
        # update runtime status
        await self._restart()

    async def stop(self) -> None:
        await self._stop()
        kresd_config_file(self._config, self.id).unlink()

    def __eq__(self, o: object) -> bool:
        return isinstance(o, type(self)) and o.type == self.type and o.id == self.id

    def __hash__(self) -> int:
        return hash(type(self)) ^ hash(self.type) ^ hash(self.id)

    async def _start(self) -> None:
        raise NotImplementedError()

    async def _stop(self) -> None:
        raise NotImplementedError()

    async def _restart(self) -> None:
        raise NotImplementedError()

    @property
    def type(self) -> SubprocessType:
        raise NotImplementedError()

    @property
    def id(self) -> KresID:
        raise NotImplementedError()


class SubprocessStatus(Enum):
    RUNNING = auto()
    FAILED = auto()
    UNKNOWN = auto()


class SubprocessController:
    """
    The common Subprocess Controller interface. This is what KresManager requires and what has to be implemented by all
    controllers.
    """

    async def is_controller_available(self, config: KresConfig) -> bool:
        """
        Returns bool, whether the controller is available with the given config
        """
        raise NotImplementedError()

    async def initialize_controller(self, config: KresConfig) -> None:
        """
        Should be called when we want to really start using the controller with a specific configuration
        """
        raise NotImplementedError()

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        """

        Must NOT be called before initialize_controller()
        """
        raise NotImplementedError()

    async def shutdown_controller(self) -> None:
        """
        Called when the manager is gracefully shutting down. Allows us to stop
        the service manager process or simply cleanup, so that we don't reuse
        the same resources in a new run.

        Must NOT be called before initialize_controller()
        """
        raise NotImplementedError()

    async def create_subprocess(
        self, subprocess_config: KresConfig, subprocess_type: SubprocessType, id_hint: KresID
    ) -> Subprocess:
        """
        Return a Subprocess object which can be operated on. The subprocess is not
        started or in any way active after this call. That has to be performaed manually
        using the returned object itself.

        Must NOT be called before initialize_controller()
        """
        raise NotImplementedError()

    async def get_subprocess_status(self) -> Dict[KresID, SubprocessStatus]:
        """
        Get a status of running subprocesses as seen by the controller. This method  actively polls
        for information.

        Must NOT be called before initialize_controller()
        """
        raise NotImplementedError()
