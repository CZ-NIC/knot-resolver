import logging
import os
import socket
from typing import Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.utils import DataParser, DataValidationException, DataValidator
from knot_resolver_manager.utils.types import LiteralEnum

logger = logging.getLogger(__name__)


def _cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except (NotImplementedError, AttributeError):
        logger.warning(
            "The number of usable CPUs could not be determined using 'os.sched_getaffinity()'."
            "Attempting to get the number of system CPUs using 'os.cpu_count()'"
        )
        cpus = os.cpu_count()
        if cpus is None:
            raise DataValidationException(
                "The number of available CPUs to automatically set the number of running"
                "'kresd' workers could not be determined."
                "The number can be specified manually in 'server:instances' configuration option."
            )
        return cpus


BackendEnum = LiteralEnum["auto", "systemd", "supervisord"]


class Management(DataParser):
    listen: str = "/tmp/manager.sock"
    backend: BackendEnum = "auto"
    rundir: str = "."


class ManagementStrict(DataValidator):
    listen: str
    backend: BackendEnum
    rundir: str

    def _validate(self) -> None:
        pass


class Server(DataParser):
    hostname: Optional[str] = None
    groupid: Optional[str] = None
    nsid: Optional[str]
    workers: Union[Literal["auto"], int] = 1
    use_cache_gc: bool = True
    management: Management = Management()


class ServerStrict(DataValidator):
    hostname: str
    groupid: Optional[str]
    nsid: Optional[str]
    workers: int
    use_cache_gc: bool
    management: ManagementStrict

    def _hostname(self, obj: Server) -> str:
        if isinstance(obj.hostname, str):
            return obj.hostname
        elif obj.hostname is None:
            return socket.gethostname()
        raise DataValidationException(f"Unexpected value for 'server.hostname': {obj.workers}")

    def _workers(self, obj: Server) -> int:
        if isinstance(obj.workers, int):
            return obj.workers
        elif obj.workers == "auto":
            return _cpu_count()
        raise DataValidationException(f"Unexpected value for 'server.workers': {obj.workers}")

    def _validate(self) -> None:
        if self.workers < 0:
            raise DataValidationException("Number of workers must be non-negative")
