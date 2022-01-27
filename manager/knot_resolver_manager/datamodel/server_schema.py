import logging
import os
import socket
from typing import Any, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.network_schema import listen_config_validate
from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DomainName,
    InterfacePort,
    IPAddressPort,
    RecordTypeEnum,
    UncheckedPath,
)
from knot_resolver_manager.exceptions import DataException
from knot_resolver_manager.utils import SchemaNode

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


BackendEnum = Literal["auto", "systemd", "supervisord"]


class WatchDogSchema(SchemaNode):
    qname: DomainName
    qtype: RecordTypeEnum


class ManagementSchema(SchemaNode):
    unix_socket: Optional[CheckedPath] = None
    ip_address: Optional[IPAddressPort] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.ip_address):
            raise ValueError("One of 'ip-address' or 'unix-socket' must be configured..")


class WebmgmtSchema(SchemaNode):
    unix_socket: Optional[CheckedPath] = None
    ip_address: Optional[IPAddressPort] = None
    interface: Optional[InterfacePort] = None
    tls: bool = False
    cert_file: Optional[CheckedPath] = None
    key_file: Optional[CheckedPath] = None

    def _validate(self) -> None:
        listen_config_validate(self)


class ServerSchema(SchemaNode):
    """
    DNS resolver server control and management configuration.

    ---
    hostname: Internal Knot Resolver hostname. Default is hostname of machine.
    groupid: Additional identifier in case more managers are running on single machine.
    nsid: Name Server Identifier (RFC 5001) which allows DNS clients to request resolver to send back its NSID along with the reply to a DNS request.
    workers: The number of running 'Knot Resolver daemon' (kresd) workers. Based on number of CPUs if set to 'auto'.
    use_cache_gc: Use cache garbage collector (kres-cache-gc) automatically.
    backend: Forces manager to use a specific service manager. Defaults to autodetection.
    watchdog: Systemd watchdog configuration. Can only be used with 'systemd' backend.
    rundir: Directory where the manager can create files and which will be manager's cwd
    management: Management API configuration.
    webmgmt: Legacy built-in web management API configuration.
    """

    class Raw(SchemaNode):
        hostname: Optional[str] = None
        groupid: Optional[str] = None
        nsid: Optional[str] = None
        workers: Union[Literal["auto"], int] = 1
        use_cache_gc: bool = True
        backend: BackendEnum = "auto"
        watchdog: Union[bool, WatchDogSchema] = True
        rundir: UncheckedPath = UncheckedPath(".")
        management: ManagementSchema = ManagementSchema({"unix-socket": "./manager.sock"})
        webmgmt: Optional[WebmgmtSchema] = None

    _PREVIOUS_SCHEMA = Raw

    hostname: str
    groupid: Optional[str]
    nsid: Optional[str]
    workers: int
    use_cache_gc: bool
    backend: BackendEnum = "auto"
    watchdog: Union[bool, WatchDogSchema]
    rundir: UncheckedPath = UncheckedPath(".")
    management: ManagementSchema
    webmgmt: Optional[WebmgmtSchema]

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
        if self.watchdog and self.backend not in ["auto", "systemd"]:
            raise ValueError("'watchdog' can only be configured for 'systemd' backend")
