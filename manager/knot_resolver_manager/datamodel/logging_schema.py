import os
from typing import Any, List, Optional, Set, Type, Union, cast

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import FilePath, TimeUnit
from knot_resolver_manager.utils.modeling import ConfigSchema
from knot_resolver_manager.utils.modeling.base_schema import is_obj_type_valid

try:
    # On Debian 10, the typing_extensions library does not contain TypeAlias.
    # We don't strictly need the import for anything except for type checking,
    # so this try-except makes sure it works either way.
    from typing_extensions import TypeAlias  # pylint: disable=ungrouped-imports
except ImportError:
    TypeAlias = None  # type: ignore


LogLevelEnum = Literal["crit", "err", "warning", "notice", "info", "debug"]
LogTargetEnum = Literal["syslog", "stderr", "stdout"]
LogGroupsEnum: TypeAlias = Literal[
    "manager",
    "supervisord",
    "cache-gc",
    ## Now the LOG_GRP_*_TAG defines, exactly from ../../../lib/log.h
    "system",
    "cache",
    "io",
    "net",
    "ta",
    "tasent",
    "tasign",
    "taupd",
    "tls",
    "gnutls",
    "tls_cl",
    "xdp",
    "doh",
    "dnssec",
    "hint",
    "plan",
    "iterat",
    "valdtr",
    "resolv",
    "select",
    "zoncut",
    "cookie",
    "statis",
    "rebind",
    "worker",
    "policy",
    "daf",
    "timejm",
    "timesk",
    "graphi",
    "prefil",
    "primin",
    "srvstl",
    "wtchdg",
    "nsid",
    "dnstap",
    "tests",
    "dotaut",
    "http",
    "contrl",
    "module",
    "devel",
    "renum",
    "exterr",
    "rules",
    "prlayr",
    # "reqdbg",... (non-displayed section of the enum)
]


class DnstapSchema(ConfigSchema):
    """
    Logging DNS queries and responses to a unix socket.

    ---
    unix_socket: Path to unix domain socket where dnstap messages will be sent.
    log_queries: Log queries from downstream in wire format.
    log_responses: Log responses to downstream in wire format.
    log_tcp_rtt: Log TCP RTT (Round-trip time).
    """

    unix_socket: FilePath
    log_queries: bool = True
    log_responses: bool = True
    log_tcp_rtt: bool = True


class DebuggingSchema(ConfigSchema):
    """
    Advanced debugging parameters for kresd (Knot Resolver daemon).

    ---
    assertion_abort: Allow the process to be aborted in case it encounters a failed assertion.
    assertion_fork: Fork and abord child kresd process to obtain a coredump, while the parent process recovers and keeps running.
    """

    assertion_abort: bool = False
    assertion_fork: TimeUnit = TimeUnit("5m")


class LoggingSchema(ConfigSchema):
    class Raw(ConfigSchema):
        """
        Logging and debugging configuration.

        ---
        level: Global logging level.
        target: Global logging stream target. "from-env" uses $KRES_LOG_TARGET and defaults to "stdout".
        groups: List of groups for which 'debug' logging level is set.
        dnssec_bogus: Logging a message for each DNSSEC validation failure.
        dnstap: Logging DNS requests and responses to a unix socket.
        debugging: Advanced debugging parameters for kresd (Knot Resolver daemon).
        """

        level: LogLevelEnum = "notice"
        target: Union[LogTargetEnum, Literal["from-env"]] = "from-env"
        groups: Optional[List[LogGroupsEnum]] = None
        dnssec_bogus: bool = False
        dnstap: Union[Literal[False], DnstapSchema] = False
        debugging: DebuggingSchema = DebuggingSchema()

    _LAYER = Raw

    level: LogLevelEnum
    target: LogTargetEnum
    groups: Optional[List[LogGroupsEnum]]
    dnssec_bogus: bool
    dnstap: Union[Literal[False], DnstapSchema]
    debugging: DebuggingSchema

    def _target(self, raw: Raw) -> LogTargetEnum:
        if raw.target == "from-env":
            target = os.environ.get("KRES_LOGGING_TARGET") or "stdout"
            if not is_obj_type_valid(target, cast(Type[Any], LogTargetEnum)):
                raise ValueError(f"logging target '{target}' read from $KRES_LOGGING_TARGET is invalid")
            return cast(LogTargetEnum, target)
        else:
            return raw.target

    def _validate(self):
        if self.groups is None:
            return

        checked: Set[str] = set()
        for i, g in enumerate(self.groups):
            if g in checked:
                raise ValueError(f"duplicate logging group '{g}' on index {i}")
            checked.add(g)
