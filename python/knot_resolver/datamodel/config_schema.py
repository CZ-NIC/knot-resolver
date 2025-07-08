import logging
import os
import socket
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

from knot_resolver.constants import API_SOCK_FILE, RUN_DIR, VERSION
from knot_resolver.datamodel.cache_schema import CacheSchema
from knot_resolver.datamodel.defer_schema import DeferSchema
from knot_resolver.datamodel.dns64_schema import Dns64Schema
from knot_resolver.datamodel.dnssec_schema import DnssecSchema
from knot_resolver.datamodel.forward_schema import ForwardSchema
from knot_resolver.datamodel.globals import Context, get_global_validation_context, set_global_validation_context
from knot_resolver.datamodel.kafka_schema import KafkaSchema
from knot_resolver.datamodel.local_data_schema import LocalDataSchema, RPZSchema, RuleSchema
from knot_resolver.datamodel.logging_schema import LoggingSchema
from knot_resolver.datamodel.lua_schema import LuaSchema
from knot_resolver.datamodel.management_schema import ManagementSchema
from knot_resolver.datamodel.monitoring_schema import MonitoringSchema
from knot_resolver.datamodel.network_schema import NetworkSchema
from knot_resolver.datamodel.options_schema import OptionsSchema
from knot_resolver.datamodel.rate_limiting_schema import RateLimitingSchema
from knot_resolver.datamodel.templates import POLICY_CONFIG_TEMPLATE, WORKER_CONFIG_TEMPLATE
from knot_resolver.datamodel.types import EscapedStr, IntPositive, WritableDir
from knot_resolver.datamodel.view_schema import ViewSchema
from knot_resolver.datamodel.webmgmt_schema import WebmgmtSchema
from knot_resolver.utils.modeling import ConfigSchema
from knot_resolver.utils.modeling.base_schema import lazy_default
from knot_resolver.utils.modeling.exceptions import AggregateDataValidationError, DataValidationError

WORKERS_MAX = 256

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


def _workers_max_count() -> int:
    c = _cpu_count()
    if c:
        return c * 10
    return WORKERS_MAX


def _get_views_tags(views: List[ViewSchema]) -> List[str]:
    tags = []
    for view in views:
        if view.tags:
            tags += [str(tag) for tag in view.tags if tag not in tags]
    return tags


def _check_local_data_tags(
    views_tags: List[str], rules_or_rpz: Union[List[RuleSchema], List[RPZSchema]]
) -> Tuple[List[str], List[DataValidationError]]:
    tags = []
    errs = []

    i = 0
    for rule in rules_or_rpz:
        tags_not_in = []
        if rule.tags:
            for tag in rule.tags:
                tag_str = str(tag)
                if tag_str not in tags:
                    tags.append(tag_str)
                if tag_str not in views_tags:
                    tags_not_in.append(tag_str)
            if len(tags_not_in) > 0:
                errs.append(
                    DataValidationError(
                        f"some tags {tags_not_in} not found in '/views' tags", f"/local-data/rules[{i}]/tags"
                    )
                )
            i += 1
    return tags, errs


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
        rate_limiting: Configuration of rate limiting.
        defer: Configuration of request prioritization (defer).
        kafka: Configuration of Apache Kafka client. Requires the optional 'kafka-python' dependency.
        """

        version: int = 1
        nsid: Optional[EscapedStr] = None
        hostname: Optional[EscapedStr] = None
        rundir: WritableDir = lazy_default(WritableDir, str(RUN_DIR))
        workers: Union[Literal["auto"], IntPositive] = IntPositive(1)
        max_workers: IntPositive = IntPositive(WORKERS_MAX)
        management: ManagementSchema = lazy_default(ManagementSchema, {"unix-socket": str(API_SOCK_FILE)})
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
        rate_limiting: Optional[RateLimitingSchema] = None
        defer: DeferSchema = DeferSchema()
        kafka: KafkaSchema = KafkaSchema()
        lua: LuaSchema = LuaSchema()

    _LAYER = Raw

    nsid: Optional[EscapedStr]
    hostname: EscapedStr
    rundir: WritableDir
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
    rate_limiting: Optional[RateLimitingSchema]
    defer: DeferSchema
    kafka: KafkaSchema
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
        # warn about '/management/unix-socket' not located in '/rundir'
        if self.management.unix_socket and self.management.unix_socket.to_path().parent != self.rundir.to_path():
            logger.warning(
                f"The management API unix-socket '{self.management.unix_socket}'"
                f" is not located in the resolver's rundir '{self.rundir}'."
                " This can lead to permissions issues."
            )

        # enforce max-workers config
        workers_max = _workers_max_count()
        if int(self.workers) > workers_max:
            raise ValueError(
                f"can't run with more workers than the recommended maximum {workers_max} or hardcoded {WORKERS_MAX}"
            )

        # sanity check
        cpu_count = _cpu_count()
        if cpu_count and int(self.workers) > 10 * cpu_count:
            raise ValueError(
                "refusing to run with more then 10 workers per cpu core, the system wouldn't behave nicely"
            )

        # get all tags from views
        views_tags = []
        if self.views:
            views_tags = _get_views_tags(self.views)

        # get local-data tags and check its existence in views
        errs = []
        local_data_tags = []
        if self.local_data.rules:
            rules_tags, rules_errs = _check_local_data_tags(views_tags, self.local_data.rules)
            errs += rules_errs
            local_data_tags += rules_tags
        if self.local_data.rpz:
            rpz_tags, rpz_errs = _check_local_data_tags(views_tags, self.local_data.rpz)
            errs += rpz_errs
            local_data_tags += rpz_tags

        # look for unused tags in /views
        unused_tags = views_tags.copy()
        for tag in local_data_tags:
            if tag in unused_tags:
                unused_tags.remove(tag)
        if len(unused_tags) > 1:
            errs.append(DataValidationError(f"unused tags {unused_tags} found", "/views"))

        # raise all validation errors
        if len(errs) == 1:
            raise errs[0]
        if len(errs) > 1:
            raise AggregateDataValidationError("/", errs)

    def render_lua(self) -> str:
        # FIXME the `cwd` argument is used only for configuring control socket path
        # it should be removed and relative path used instead as soon as issue
        # https://gitlab.nic.cz/knot/knot-resolver/-/issues/720 is fixed
        return WORKER_CONFIG_TEMPLATE.render(cfg=self, cwd=os.getcwd())

    def render_lua_policy(self) -> str:
        return POLICY_CONFIG_TEMPLATE.render(cfg=self, cwd=os.getcwd())


def get_rundir_without_validation(data: Dict[str, Any]) -> WritableDir:
    """
    Without fully parsing, try to get a rundir from a raw config data, otherwise use default.
    Attempts a dir validation to produce a good error message.

    Used for initial manager startup.
    """

    return WritableDir(data["rundir"] if "rundir" in data else str(RUN_DIR), object_path="/rundir")


def kres_config_json_schema() -> Dict[str, Any]:
    """
    At this moment, to create any instance of 'ConfigSchema' even with default values, it is necessary to set the global context.
    In the case of generating a JSON schema, strict validation must be turned off, otherwise it may happen that the creation of the JSON schema fails,
    It may fail due to non-existence of the directory/file or their rights.
    This should be fixed in the future. For more info, see 'datamodel.globals.py' module.
    """

    context = get_global_validation_context()
    set_global_validation_context(Context(None, False))

    schema = KresConfig.json_schema(
        schema_id=f"https://www.knot-resolver.cz/documentation/v{VERSION}/_static/config.schema.json",
        title="Knot Resolver configuration JSON schema",
        description=f"Version Knot Resolver {VERSION}",
    )
    # setting back to previous values
    set_global_validation_context(context)

    return schema
