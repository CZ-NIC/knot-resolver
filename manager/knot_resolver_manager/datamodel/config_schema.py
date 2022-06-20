import logging
import os
import socket
import sys
from typing import Any, Dict, List, Optional, Union

from jinja2 import Environment, FileSystemLoader, Template
from typing_extensions import Literal

from knot_resolver_manager.datamodel.cache_schema import CacheSchema
from knot_resolver_manager.datamodel.dns64_schema import Dns64Schema
from knot_resolver_manager.datamodel.dnssec_schema import DnssecSchema
from knot_resolver_manager.datamodel.forward_zone_schema import ForwardZoneSchema
from knot_resolver_manager.datamodel.logging_schema import LoggingSchema
from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.datamodel.management_schema import ManagementSchema
from knot_resolver_manager.datamodel.monitoring_schema import MonitoringSchema
from knot_resolver_manager.datamodel.network_schema import NetworkSchema
from knot_resolver_manager.datamodel.options_schema import OptionsSchema
from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.datamodel.slice_schema import SliceSchema
from knot_resolver_manager.datamodel.static_hints_schema import StaticHintsSchema
from knot_resolver_manager.datamodel.stub_zone_schema import StubZoneSchema
from knot_resolver_manager.datamodel.supervisor_schema import SupervisorSchema
from knot_resolver_manager.datamodel.types.types import IDPattern, IntPositive, UncheckedPath
from knot_resolver_manager.datamodel.view_schema import ViewSchema
from knot_resolver_manager.datamodel.webmgmt_schema import WebmgmtSchema
from knot_resolver_manager.exceptions import DataException
from knot_resolver_manager.utils import SchemaNode

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


class KresConfig(SchemaNode):
    class Raw(SchemaNode):
        """
        Knot Resolver declarative configuration.

        ---
        id: System-wide unique identifier of this instance. Used for grouping logs and tagging workers.
        nsid: Name Server Identifier (RFC 5001) which allows DNS clients to request resolver to send back its NSID along with the reply to a DNS request.
        hostname: Internal DNS resolver hostname. Default is machine hostname.
        rundir: Directory where the resolver can create files and which will be it's cwd.
        workers: The number of running kresd (Knot Resolver daemon) workers. If set to 'auto', it is equal to number of CPUs available.
        management: Configuration of management HTTP API.
        webmgmt: Configuration of legacy web management endpoint.
        supervisor: Proceses supervisor configuration.
        options: Fine-tuning global parameters of DNS resolver operation.
        network: Network connections and protocols configuration.
        static_hints: Static hints for forward records (A/AAAA) and reverse records (PTR)
        views: List of views and its configuration.
        slices: Split the entire DNS namespace into distinct slices.
        policy: List of policy rules and its configuration.
        rpz: List of Response Policy Zones and its configuration.
        stub_zones: List of Stub Zones and its configuration.
        forward_zones: List of Forward Zones and its configuration.
        cache: DNS resolver cache configuration.
        dnssec: Disable DNSSEC, enable with defaults or set new configuration.
        dns64: Disable DNS64 (RFC 6147), enable with defaults or set new configuration.
        logging: Logging and debugging configuration.
        monitoring: Metrics exposisition configuration (Prometheus, Graphite)
        lua: Custom Lua configuration.
        """

        id: IDPattern
        nsid: Optional[str] = None
        hostname: Optional[str] = None
        rundir: UncheckedPath = UncheckedPath(".")
        workers: Union[Literal["auto"], IntPositive] = IntPositive(1)
        management: ManagementSchema = ManagementSchema({"unix-socket": "./manager.sock"})
        webmgmt: Optional[WebmgmtSchema] = None
        supervisor: SupervisorSchema = SupervisorSchema()
        options: OptionsSchema = OptionsSchema()
        network: NetworkSchema = NetworkSchema()
        static_hints: StaticHintsSchema = StaticHintsSchema()
        views: Optional[Dict[str, ViewSchema]] = None
        slices: Optional[List[SliceSchema]] = None
        policy: Optional[List[PolicySchema]] = None
        rpz: Optional[List[RPZSchema]] = None
        stub_zones: Optional[List[StubZoneSchema]] = None
        forward_zones: Optional[List[ForwardZoneSchema]] = None
        cache: CacheSchema = CacheSchema()
        dnssec: Union[bool, DnssecSchema] = True
        dns64: Union[bool, Dns64Schema] = False
        logging: LoggingSchema = LoggingSchema()
        monitoring: MonitoringSchema = MonitoringSchema()
        lua: LuaSchema = LuaSchema()

    _PREVIOUS_SCHEMA = Raw

    id: IDPattern
    nsid: Optional[str]
    hostname: str
    rundir: UncheckedPath
    workers: IntPositive
    management: ManagementSchema
    webmgmt: Optional[WebmgmtSchema]
    supervisor: SupervisorSchema
    options: OptionsSchema
    network: NetworkSchema
    static_hints: StaticHintsSchema
    views: Optional[Dict[str, ViewSchema]]
    slices: Optional[List[SliceSchema]]
    policy: Optional[List[PolicySchema]]
    rpz: Optional[List[RPZSchema]]
    stub_zones: Optional[List[StubZoneSchema]]
    forward_zones: Optional[List[ForwardZoneSchema]]
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
            return IntPositive(_cpu_count())
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
        try:
            cpu_count = _cpu_count()
            if int(self.workers) > 10 * cpu_count:
                raise ValueError("refusing to run with more then instances 10 instances per cpu core")
        except DataException:
            # sometimes, we won't be able to get information about the cpu count
            pass

    def render_lua(self) -> str:
        # FIXME the `cwd` argument is used only for configuring control socket path
        # it should be removed and relative path used instead as soon as issue
        # https://gitlab.nic.cz/knot/knot-resolver/-/issues/720 is fixed
        return _MAIN_TEMPLATE.render(cfg=self, cwd=os.getcwd())  # pyright: reportUnknownMemberType=false
