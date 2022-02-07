from typing import List, Optional, Union

from typing_extensions import Literal, TypeAlias

from knot_resolver_manager.datamodel.types import CheckedPath, TimeUnit
from knot_resolver_manager.utils import SchemaNode

LogLevelEnum = Literal["crit", "err", "warning", "notice", "info", "debug"]
LogTargetEnum = Literal["syslog", "stderr", "stdout"]
LogGroupsEnum: TypeAlias = Literal[
    "manager",
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
    "zimprt",
    "zscann",
    "doh",
    "dnssec",
    "hint",
    "plan",
    "iterat",
    "valdtr",
    "resolv",
    "select",
    "zonecut",
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
    "reqdbg",
]


class DnstapSchema(SchemaNode):
    """
    Logging DNS queries and responses to a unix socket.

    ---
    unix_socket: Path to unix domain socket where dnstap messages will be sent.
    log_queries: Log queries from downstream in wire format.
    log_responses: Log responses to downstream in wire format.
    log_tcp_rtt: Log TCP RTT (Round-trip time).
    """

    unix_socket: CheckedPath
    log_queries: bool = True
    log_responses: bool = True
    log_tcp_rtt: bool = True


class DebuggingSchema(SchemaNode):
    """
    Advanced debugging parameters for kresd (Knot Resolver daemon).

    ---
    assertion_abort: Allow the process to be aborted in case it encounters a failed assertion.
    assertion_fork: Fork and abord child kresd process to obtain a coredump, while the parent process recovers and keeps running.
    """

    assertion_abort: bool = False
    assertion_fork: TimeUnit = TimeUnit("5m")


class LoggingSchema(SchemaNode):
    """
    Logging and debugging configuration.

    ---
    level: Global logging level.
    target: Global logging stream target.
    groups: List of groups for which 'debug' logging level is set.
    dnssec_bogus: Logging a message for each DNSSEC validation failure.
    dnstap: Logging DNS requests and responses to a unix socket.
    debugging: Advanced debugging parameters for kresd (Knot Resolver daemon).
    """

    level: LogLevelEnum = "notice"
    target: Optional[LogTargetEnum] = None
    groups: Optional[List[LogGroupsEnum]] = None
    dnssec_bogus: bool = False
    dnstap: Union[Literal[False], DnstapSchema] = False
    debugging: DebuggingSchema = DebuggingSchema()
