import os
from typing import Any, List, Literal, Optional, Set, Type, Union, cast

from knot_resolver.datamodel.types import WritableFilePath
from knot_resolver.utils.modeling import ConfigSchema
from knot_resolver.utils.modeling.base_schema import is_obj_type_valid

LogLevelEnum = Literal["crit", "err", "warning", "notice", "info", "debug"]
LogTargetEnum = Literal["syslog", "stderr", "stdout"]
LogGroupsEnum = Literal[
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
    "defer",
    # "reqdbg",... (non-displayed section of the enum)
]


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
    class Raw(ConfigSchema):
        """
        Logging and debugging configuration.

        ---
        level: Global logging level.
        target: Global logging stream target. "from-env" uses $KRES_LOGGING_TARGET and defaults to "stdout".
        groups: List of groups for which 'debug' logging level is set.
        dnstap: Logging DNS requests and responses to a unix socket.
        """

        level: LogLevelEnum = "notice"
        target: Union[LogTargetEnum, Literal["from-env"]] = "from-env"
        groups: Optional[List[LogGroupsEnum]] = None
        dnstap: DnstapSchema = DnstapSchema()

    _LAYER = Raw

    level: LogLevelEnum
    target: LogTargetEnum
    groups: Optional[List[LogGroupsEnum]]
    dnstap: DnstapSchema

    def _target(self, raw: Raw) -> LogTargetEnum:
        if raw.target == "from-env":
            target = os.environ.get("KRES_LOGGING_TARGET") or "stdout"
            if not is_obj_type_valid(target, cast(Type[Any], LogTargetEnum)):
                raise ValueError(f"logging target '{target}' read from $KRES_LOGGING_TARGET is invalid")
            return cast(LogTargetEnum, target)
        return raw.target

    def _validate(self):
        if self.groups is None:
            return

        checked: Set[str] = set()
        for i, g in enumerate(self.groups):
            if g in checked:
                raise ValueError(f"duplicate logging group '{g}' on index {i}")
            checked.add(g)
