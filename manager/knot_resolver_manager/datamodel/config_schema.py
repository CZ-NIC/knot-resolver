import logging
import os
import socket
import sys
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader, Template
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
from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.datamodel.slice_schema import SliceSchema
from knot_resolver_manager.datamodel.stub_zone_schema import StubZoneSchema
from knot_resolver_manager.datamodel.types import IntPositive
from knot_resolver_manager.datamodel.types.files import UncheckedPath
from knot_resolver_manager.datamodel.view_schema import ViewSchema
from knot_resolver_manager.datamodel.webmgmt_schema import WebmgmtSchema
from knot_resolver_manager.utils.modeling import ConfigSchema
from knot_resolver_manager.utils.modeling.base_schema import lazy_default

logger = logging.getLogger(__name__)


def _get_templates_dir() -> str:
    module = sys.modules["knot_resolver_manager.datamodel"].__file__
    if module:
        templates_dir = os.path.join(os.path.dirname(module), "templates")
        if os.path.isdir(templates_dir):
            return templates_dir
        raise NotADirectoryError(f"the templates dir '{templates_dir}' is not a directory or does not exist")
    raise OSError("package 'knot_resolver_manager.datamodel' cannot be located or loaded")


_TEMPLATES_DIR = _get_templates_dir()


def template_from_str(template: str) -> Template:
    ldr = FileSystemLoader(_TEMPLATES_DIR)
    env = Environment(trim_blocks=True, lstrip_blocks=True, loader=ldr)
    return env.from_string(template)


def _import_lua_template() -> Template:
    path = os.path.join(_TEMPLATES_DIR, "config.lua.j2")
    with open(path, "r", encoding="UTF-8") as file:
        template = file.read()
    return template_from_str(template)


_MAIN_TEMPLATE = _import_lua_template()


def _cpu_count() -> Optional[int]:
    try:
        return len(os.sched_getaffinity(0))
    except (NotImplementedError, AttributeError):
        logger.warning("The number of usable CPUs could not be determined using 'os.sched_getaffinity()'.")
        cpus = os.cpu_count()
        if cpus is None:
            logger.warning("The number of usable CPUs could not be determined using 'os.cpu_count()'.")
        return cpus


def _default_max_worker_count() -> Optional[int]:
    c = _cpu_count()
    if c is not None:
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
        slices: Split the entire DNS namespace into distinct slices.
        policy: List of policy rules and its configuration.
        rpz: List of Response Policy Zones and its configuration.
        stub_zones: List of Stub Zones and its configuration.
        forward: List of Forward Zones and its configuration.
        cache: DNS resolver cache configuration.
        dnssec: Disable DNSSEC, enable with defaults or set new configuration.
        dns64: Disable DNS64 (RFC 6147), enable with defaults or set new configuration.
        logging: Logging and debugging configuration.
        monitoring: Metrics exposisition configuration (Prometheus, Graphite)
        lua: Custom Lua configuration.
        """

        version: int = 1
        nsid: Optional[str] = None
        hostname: Optional[str] = None
        rundir: UncheckedPath = UncheckedPath("/var/run/knot-resolver")
        workers: Union[Literal["auto"], IntPositive] = IntPositive(1)
        max_workers: IntPositive = IntPositive(_default_max_worker_count())
        management: ManagementSchema = lazy_default(ManagementSchema, {"unix-socket": "./manager.sock"})
        webmgmt: Optional[WebmgmtSchema] = None
        options: OptionsSchema = OptionsSchema()
        network: NetworkSchema = NetworkSchema()
        views: Optional[List[ViewSchema]] = None
        local_data: LocalDataSchema = LocalDataSchema()
        slices: Optional[List[SliceSchema]] = None
        policy: Optional[List[PolicySchema]] = None
        rpz: Optional[List[RPZSchema]] = None
        stub_zones: Optional[List[StubZoneSchema]] = None
        forward: Optional[List[ForwardSchema]] = None
        cache: CacheSchema = CacheSchema()
        dnssec: Union[bool, DnssecSchema] = True
        dns64: Union[bool, Dns64Schema] = False
        logging: LoggingSchema = LoggingSchema()
        monitoring: MonitoringSchema = MonitoringSchema()
        lua: LuaSchema = LuaSchema()

    _LAYER = Raw

    nsid: Optional[str]
    hostname: str
    rundir: UncheckedPath
    workers: IntPositive
    max_workers: IntPositive
    management: ManagementSchema
    webmgmt: Optional[WebmgmtSchema]
    options: OptionsSchema
    network: NetworkSchema
    views: Optional[List[ViewSchema]]
    local_data: LocalDataSchema
    slices: Optional[List[SliceSchema]]
    policy: Optional[List[PolicySchema]]
    rpz: Optional[List[RPZSchema]]
    stub_zones: Optional[List[StubZoneSchema]]
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
        return _MAIN_TEMPLATE.render(cfg=self, cwd=os.getcwd())  # pyright: reportUnknownMemberType=false


def get_rundir_without_validation(data: Dict[str, Any]) -> UncheckedPath:
    """
    Without fully parsing, try to get a rundir from a raw config data. When it fails,
    attempts a full validation to produce a good error message.

    Used for initial manager startup.
    """

    if "rundir" in data:
        rundir = data["rundir"]
    else:
        _ = KresConfig(data)  # this should throw a descriptive error
        assert False

    return UncheckedPath(rundir, object_path="/rundir")
