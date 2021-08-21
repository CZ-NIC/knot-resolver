import logging
from typing import Iterable, List, Set

from knot_resolver_manager.compat.asyncio import to_thread
from knot_resolver_manager.kres_id import KresID, alloc_from_string
from knot_resolver_manager.kresd_controller.interface import (
    Subprocess,
    SubprocessController,
    SubprocessInfo,
    SubprocessType,
)

from .config import (
    SupervisordConfig,
    create_id,
    is_supervisord_available,
    is_supervisord_running,
    list_ids_from_existing_config,
    list_subprocesses,
    restart,
    start_supervisord,
    stop_supervisord,
    update_config,
)

logger = logging.getLogger(__name__)


class SupervisordSubprocess(Subprocess):
    def __init__(self, controller: "SupervisordSubprocessController", id_: KresID, type_: SubprocessType):
        self._controller: "SupervisordSubprocessController" = controller
        self._id: KresID = id_
        self._type: SubprocessType = type_

    @property
    def type(self) -> SubprocessType:
        return self._type

    @property
    def id(self) -> str:
        return create_id(self._type, self._id)

    async def is_running(self) -> bool:
        return self._controller.should_be_running(self)

    async def start(self) -> None:
        return await self._controller.start_subprocess(self)

    async def stop(self) -> None:
        return await self._controller.stop_subprocess(self)

    async def restart(self) -> None:
        return await self._controller.restart_subprocess(self)


class SupervisordSubprocessController(SubprocessController):
    def __init__(self):
        self._running_instances: Set[SupervisordSubprocess] = set()

    def __str__(self):
        return "supervisord"

    def should_be_running(self, subprocess: SupervisordSubprocess):
        return subprocess in self._running_instances

    async def is_controller_available(self) -> bool:
        res = await is_supervisord_available()
        if not res:
            logger.info("Failed to find usable supervisord.")

        logger.debug("Detection - supervisord controller is available for use")
        return res

    async def _update_config_with_real_state(self):
        running = await is_supervisord_running()
        if running:
            ids = await list_ids_from_existing_config()
            for tp, id_ in ids:
                self._running_instances.add(SupervisordSubprocess(self, alloc_from_string(id_), tp))

    async def get_all_running_instances(self) -> Iterable[Subprocess]:
        await self._update_config_with_real_state()
        return iter(self._running_instances)

    def _create_config(self) -> SupervisordConfig:
        return SupervisordConfig(instances=self._running_instances)  # type: ignore

    async def initialize_controller(self) -> None:
        if not await is_supervisord_running():
            config = self._create_config()
            await start_supervisord(config)

    async def shutdown_controller(self) -> None:
        await stop_supervisord()

    async def start_subprocess(self, subprocess: SupervisordSubprocess):
        assert subprocess not in self._running_instances
        self._running_instances.add(subprocess)
        await update_config(self._create_config())

    async def stop_subprocess(self, subprocess: SupervisordSubprocess):
        assert subprocess in self._running_instances
        self._running_instances.remove(subprocess)
        await update_config(self._create_config())

    async def restart_subprocess(self, subprocess: SupervisordSubprocess):
        assert subprocess in self._running_instances
        await restart(subprocess.id)

    async def create_subprocess(self, subprocess_type: SubprocessType, id_hint: KresID) -> Subprocess:
        return SupervisordSubprocess(self, id_hint, subprocess_type)

    async def get_subprocess_info(self) -> List[SubprocessInfo]:
        return await to_thread(list_subprocesses)
