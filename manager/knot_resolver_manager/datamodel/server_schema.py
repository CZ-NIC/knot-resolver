import logging
import os
import socket
from typing import Any, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DNSRecordTypeEnum,
    DomainName,
    InterfacePort,
    IntPositive,
    IPAddressPort,
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
    """
    Configuration of systemd watchdog.

    ---
    qname: Name to internaly query for.
    qtype: DNS type to internaly query for.
    """

    qname: DomainName
    qtype: DNSRecordTypeEnum


class ManagementSchema(SchemaNode):
    """
    Configuration of management HTTP API.

    ---
    unix_socket: Path to unix domain socket to listen to.
    interface: IP address and port number to listen to.
    """

    unix_socket: Optional[CheckedPath] = None
    interface: Optional[IPAddressPort] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")


class WebmgmtSchema(SchemaNode):
    """
    Configuration of legacy web management endpoint.

    ---
    unix_socket: Path to unix domain socket to listen to.
    interface: IP address or interface name with port number to listen to.
    tls: Enable/disable TLS.
    cert_file: Path to certificate file.
    key_file: Path to certificate key.
    """

    unix_socket: Optional[CheckedPath] = None
    interface: Optional[InterfacePort] = None
    tls: bool = False
    cert_file: Optional[CheckedPath] = None
    key_file: Optional[CheckedPath] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")


class ServerSchema(SchemaNode):
    class Raw(SchemaNode):
        """
        DNS server control and management configuration.

        ---
        hostname: Internal DNS resolver hostname. Default is machine hostname.
        nsid: Name Server Identifier (RFC 5001) which allows DNS clients to request resolver to send back its NSID along with the reply to a DNS request.
        workers: The number of running kresd (Knot Resolver daemon) workers. If set to 'auto', it is equal to number of CPUs available.
        use_cache_gc: Use (start) kres-cache-gc (cache garbage collector) automatically.
        backend: Forces the manager to use a specific service supervisor.
        watchdog: Disable systemd watchdog, enable with defaults or set new configuration. Can only be used with 'systemd' backend.
        rundir: Directory where the resolver can create files and which will be it's cwd.
        management: Configuration of management HTTP API.
        webmgmt: Configuration of legacy web management endpoint.
        """

        hostname: Optional[str] = None
        nsid: Optional[str] = None
        workers: Union[Literal["auto"], IntPositive] = IntPositive(1)
        use_cache_gc: bool = True
        backend: BackendEnum = "auto"
        watchdog: Union[bool, WatchDogSchema] = True
        rundir: UncheckedPath = UncheckedPath(".")
        management: ManagementSchema = ManagementSchema({"unix-socket": "./manager.sock"})
        webmgmt: Optional[WebmgmtSchema] = None

    _PREVIOUS_SCHEMA = Raw

    hostname: str
    nsid: Optional[str]
    workers: IntPositive
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
            return IntPositive(_cpu_count())
        return obj.workers

    def _validate(self) -> None:
        try:
            cpu_count = _cpu_count()
            if int(self.workers) > 10 * cpu_count:
                raise ValueError("refusing to run with more then instances 10 instances per cpu core")
        except DataException:
            # sometimes, we won't be able to get information about the cpu count
            pass

        if self.watchdog and self.backend not in ["auto", "systemd"]:
            raise ValueError("'watchdog' can only be configured for 'systemd' backend")
