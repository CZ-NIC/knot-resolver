import logging
import os
import socket
from typing import Any, Dict, List, Optional, Union

from typing_extensions import Literal

from knot_resolver_manager.constants import MAX_WORKERS
from knot_resolver_manager.datamodel.cache_schema import CacheSchema
from knot_resolver_manager.datamodel.dns64_schema import Dns64Schema
from knot_resolver_manager.datamodel.dnssec_schema import DnssecSchema
from knot_resolver_manager.datamodel.forward_schema import ForwardSchema
from knot_resolver_manager.datamodel.local_data_schema import LocalDataSchema
from knot_resolver_manager.datamodel.logging_schema import LoggingSchema
from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.datamodel.management_schema import ManagementSchema
from knot_resolver_manager.datamodel.monitoring_schema import MonitoringSchema
from knot_resolver_manager.datamodel.network_schema import NetworkSchema
from knot_resolver_manager.datamodel.options_schema import OptionsSchema
from knot_resolver_manager.datamodel.templates import MAIN_TEMPLATE
from knot_resolver_manager.datamodel.types import Dir, EscapedStr, IntPositive
from knot_resolver_manager.datamodel.view_schema import ViewSchema
from knot_resolver_manager.datamodel.webmgmt_schema import WebmgmtSchema
from knot_resolver_manager.utils.modeling import ConfigSchema
from knot_resolver_manager.utils.modeling.base_schema import lazy_default

_DEFAULT_RUNDIR = "/var/run/knot-resolver"

DEFAULT_MANAGER_API_SOCK = _DEFAULT_RUNDIR + "/manager.sock"

logger = logging.getLogger(__name__)


def _cpu_count() -> Optional[int]:
    try:
        return len(os.sched_getaffinity(0))
    except (NotImplementedError, AttributeError):
        logger.warning("The number of usable CPUs could not be determined using 'os.sched_getaffinity()'.")
        cpus = os.cpu_count()
        if cpus is None:
            logger.warning("The number of usable CPUs could not be determined using 'os.cpu_count()'.")
        return cpus


def _default_max_worker_count() -> int:
    c = _cpu_count()
    if c:
        return c * 10
    return MAX_WORKERS


class KresConfig(ConfigSchema):
    class Raw(ConfigSchema):
        """
        Knot Resolver declarative configuration.

        ---
        version: Version of the configuration schema. By default it is the latest supported by the resolver, but couple of versions back are be supported as well.
        nsid: Name Server Identifier (RFC 5001) which allows DNS clients to request resolver to send back its NSID along with the reply to a DNS request.
        hostname: Internal DNS resolver hostname. Default is machine hostname.
        rundir: Directory where the resolver can create files and which will be it's cwd.
        workers: The number of running kresd (Knot Resolver daemon) workers. If set to 'auto', it is equal to number of CPUs available.
        max_workers: The maximum number of workers allowed. Cannot be changed in runtime.
        management: Configuration of management HTTP API.
        webmgmt: Configuration of legacy web management endpoint.
        options: Fine-tuning global parameters of DNS resolver operation.
        network: Network connections and protocols configuration.
        views: List of views and its configuration.
        local_data: Local data for forward records (A/AAAA) and reverse records (PTR).
        forward: List of Forward Zones and its configuration.
        cache: DNS resolver cache configuration.
        dnssec: Disable DNSSEC, enable with defaults or set new configuration.
        dns64: Disable DNS64 (RFC 6147), enable with defaults or set new configuration.
        logging: Logging and debugging configuration.
        monitoring: Metrics exposisition configuration (Prometheus, Graphite)
        lua: Custom Lua configuration.
        """

        version: int = 1
        nsid: Optional[EscapedStr] = None
        hostname: Optional[EscapedStr] = None
        rundir: Dir = lazy_default(Dir, _DEFAULT_RUNDIR)
        workers: Union[Literal["auto"], IntPositive] = IntPositive(1)
        max_workers: IntPositive = IntPositive(_default_max_worker_count())
        management: ManagementSchema = lazy_default(ManagementSchema, {"unix-socket": DEFAULT_MANAGER_API_SOCK})
        webmgmt: Optional[WebmgmtSchema] = None
        options: OptionsSchema = OptionsSchema()
        network: NetworkSchema = NetworkSchema()
        views: Optional[List[ViewSchema]] = None
        local_data: LocalDataSchema = LocalDataSchema()
        forward: Optional[List[ForwardSchema]] = None
        cache: CacheSchema = lazy_default(CacheSchema, {})
        dnssec: Union[bool, DnssecSchema] = True
        dns64: Union[bool, Dns64Schema] = False
        logging: LoggingSchema = LoggingSchema()
        monitoring: MonitoringSchema = MonitoringSchema()
        lua: LuaSchema = LuaSchema()

    _LAYER = Raw

    nsid: Optional[EscapedStr]
    hostname: EscapedStr
    rundir: Dir
    workers: IntPositive
    max_workers: IntPositive
    management: ManagementSchema
    webmgmt: Optional[WebmgmtSchema]
    options: OptionsSchema
    network: NetworkSchema
    views: Optional[List[ViewSchema]]
    local_data: LocalDataSchema
    forward: Optional[List[ForwardSchema]]
    cache: CacheSchema
    dnssec: Union[Literal[False], DnssecSchema]
    dns64: Union[Literal[False], Dns64Schema]
    logging: LoggingSchema
    monitoring: MonitoringSchema
    lua: LuaSchema

    def _hostname(self, obj: Raw) -> Any:
        if obj.hostname is None:
            return socket.gethostname()
        return obj.hostname

    def _workers(self, obj: Raw) -> Any:
        if obj.workers == "auto":
            count = _cpu_count()
            if count:
                return IntPositive(count)
            raise ValueError(
                "The number of available CPUs to automatically set the number of running 'kresd' workers could not be determined."
                "The number of workers can be configured manually in 'workers' option."
            )
        return obj.workers

    def _dnssec(self, obj: Raw) -> Any:
        if obj.dnssec is True:
            return DnssecSchema()
        return obj.dnssec

    def _dns64(self, obj: Raw) -> Any:
        if obj.dns64 is True:
            return Dns64Schema()
        return obj.dns64

    def _validate(self) -> None:
        # enforce max-workers config
        if int(self.workers) > int(self.max_workers):
            raise ValueError(f"can't run with more workers then the configured maximum {self.max_workers}")

        # sanity check
        cpu_count = _cpu_count()
        if cpu_count and int(self.workers) > 10 * cpu_count:
            raise ValueError(
                "refusing to run with more then 10 workers per cpu core, the system wouldn't behave nicely"
            )

    def render_lua(self) -> str:
        # FIXME the `cwd` argument is used only for configuring control socket path
        # it should be removed and relative path used instead as soon as issue
        # https://gitlab.nic.cz/knot/knot-resolver/-/issues/720 is fixed
        return MAIN_TEMPLATE.render(cfg=self, cwd=os.getcwd())


def get_rundir_without_validation(data: Dict[str, Any]) -> Dir:
    """
    Without fully parsing, try to get a rundir from a raw config data, otherwise use default.
    Attempts a dir validation to produce a good error message.

    Used for initial manager startup.
    """

    return Dir(data["rundir"] if "rundir" in data else _DEFAULT_RUNDIR, object_path="/rundir")
