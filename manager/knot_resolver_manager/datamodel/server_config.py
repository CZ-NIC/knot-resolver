import logging
import os
import socket
from typing import Any, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import AnyPath, Listen
from knot_resolver_manager.exceptions import DataException
from knot_resolver_manager.utils import SchemaNode
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
            raise DataException(
                "The number of available CPUs to automatically set the number of running"
                "'kresd' workers could not be determined."
                "The number can be specified manually in 'server:instances' configuration option."
            )
        return cpus


BackendEnum = LiteralEnum["auto", "systemd", "supervisord"]


class Management(SchemaNode):
    listen: Listen = Listen({"unix-socket": "/tmp/manager.sock"})
    backend: BackendEnum = "auto"
    rundir: AnyPath = AnyPath(".")


class Webmgmt(SchemaNode):
    listen: Listen
    tls: bool = False
    cert_file: Optional[AnyPath] = None
    key_file: Optional[AnyPath] = None


class Server(SchemaNode):
    class Raw(SchemaNode):
        hostname: Optional[str] = None
        groupid: Optional[str] = None
        nsid: Optional[str] = None
        workers: Union[Literal["auto"], int] = 1
        use_cache_gc: bool = True
        management: Management = Management()
        webmgmt: Optional[Webmgmt] = None

    _PREVIOUS_SCHEMA = Raw

    hostname: str
    groupid: Optional[str]
    nsid: Optional[str]
    workers: int
    use_cache_gc: bool
    management: Management
    webmgmt: Optional[Webmgmt]

    def _hostname(self, obj: Raw) -> Any:
        if obj.hostname is None:
            return socket.gethostname()
        return obj.hostname

    def _workers(self, obj: Raw) -> Any:
        if obj.workers == "auto":
            return _cpu_count()
        return obj.workers

    def _validate(self) -> None:
        if self.workers < 0:
            raise ValueError("Number of workers must be non-negative")
