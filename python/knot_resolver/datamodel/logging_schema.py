import os
from typing import Any, List, Literal, Optional, Set, Type, Union, cast

from knot_resolver.datamodel.types import WritableFilePath
from knot_resolver.utils.modeling import ConfigSchema
from knot_resolver.utils.modeling.base_schema import is_obj_type_valid

LogLevelEnum = Literal["crit", "err", "warning", "notice", "info", "debug"]
LogTargetEnum = Literal["syslog", "stderr", "stdout"]

LogGroupsProcessesEnum = Literal[
    "manager",
    "supervisord",
    "policy-loader",
    "kresd",
    "cache-gc",
]

LogGroupsManagerEnum = Literal[
    "files",
    "metrics",
    "server",
]

LogGroupsKresdEnum = Literal[
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
    "defer",
    "doq",
    "ngtcp2",
    # "reqdbg",... (non-displayed section of the enum)
]

LogGroupsEnum = Literal[LogGroupsProcessesEnum, LogGroupsManagerEnum, LogGroupsKresdEnum]


class DnstapSchema(ConfigSchema):
    """
    Logging DNS queries and responses to a unix socket.

    ---
    enable: Enable/disable DNS queries logging.
    unix_socket: Path to unix domain socket where dnstap messages will be sent.
    log_queries: Log queries from downstream in wire format.
    log_responses: Log responses to downstream in wire format.
    log_tcp_rtt: Log TCP RTT (Round-trip time).
    """

    enable: bool = False
    unix_socket: Optional[WritableFilePath] = None
    log_queries: bool = False
    log_responses: bool = False
    log_tcp_rtt: bool = False

    def _validate(self) -> None:
        if self.enable and self.unix_socket is None:
            raise ValueError("DNS queries logging enabled, but 'unix-socket' not specified")


class LoggingSchema(ConfigSchema):
    """
    Logging and debugging configuration.

    ---
    level: Global logging level. If not configured, the logging level parsed from the program arguments is used (default 'notice').
    target: Global logging stream target. If not configured, the logging target parsed from the program arguments is used (default 'stderr').
    groups: List of groups for which 'debug' logging level is set.
    dnstap: Logging DNS requests and responses to a unix socket.
    """

    level: Optional[LogLevelEnum] = None
    target: Optional[LogTargetEnum] = None
    groups: Optional[List[LogGroupsEnum]] = None
    dnstap: DnstapSchema = DnstapSchema()

    def _validate(self) -> None:
        if self.groups is None:
            return

        checked: Set[str] = set()
        for i, g in enumerate(self.groups):
            if g in checked:
                raise ValueError(f"duplicate logging group '{g}' on index {i}")
            checked.add(g)
