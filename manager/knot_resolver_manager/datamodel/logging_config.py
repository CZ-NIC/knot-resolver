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
    Logging DNS queries and responses to a unix socket

    ---
    unix_socket: The unix socket file where dnstap messages will be sent.
    log_queries: If true queries from downstream in wire format will be logged.
    log_responses: If true responses to downstream in wire format will be logged.
    log_tcp_rtt: If true TCP RTT (Round-trip time) will be logged.
    """

    unix_socket: CheckedPath
    log_queries: bool = True
    log_responses: bool = True
    log_tcp_rtt: bool = True


class DebuggingSchema(SchemaNode):
    assertion_abort: bool = False
    assertion_fork: TimeUnit = TimeUnit("5m")


class LoggingSchema(SchemaNode):
    """
    Logging and debugging configuration.

    ---
    level: Logging level for all processes.
    target: Logging stream target for all processes.
    groups: List of groups for which 'debug' logging level is set.
    dnssec_bogus: Logging a message for each DNSSEC validation failure.
    dnstap: Logging DNS requests and responses to a unix socket.
    debugging: Advanced debugging parameters for Knot Resolver daemon (kresd).
    """

    level: LogLevelEnum = "notice"
    target: Optional[LogTargetEnum] = None
    groups: Optional[List[LogGroupsEnum]] = None
    dnssec_bogus: bool = False
    dnstap: Union[Literal[False], DnstapSchema] = False
    debugging: DebuggingSchema = DebuggingSchema()
