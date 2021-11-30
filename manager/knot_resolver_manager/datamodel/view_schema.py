from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPNetwork
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

# FLAGS from https://knot-resolver.readthedocs.io/en/stable/lib.html?highlight=options#c.kr_qflags
FlagsEnum = LiteralEnum[
    "no-minimize",
    "no-ipv4",
    "no-ipv6",
    "tcp",
    "resolved",
    "await-ipv4",
    "await-ipv6",
    "await-cut",
    "no-edns",
    "cached",
    "no-cache",
    "expiring",
    "allow_local",
    "dnssec-want",
    "dnssec-bogus",
    "dnssec-insecure",
    "dnssec-cd",
    "stub",
    "always-cut",
    "dnssec-wexpand",
    "permissive",
    "strict",
    "badcookie-again",
    "cname",
    "reorder-rr",
    "trace",
    "no-0x20",
    "dnssec-nods",
    "dnssec-optout",
    "nonauth",
    "forward",
    "dns64-mark",
    "cache-tried",
    "no-ns-found",
    "pkt-is-sane",
    "dns64-disable",
]


class ViewSchema(SchemaNode):
    subnets: Optional[List[IPNetwork]] = None
    tsig: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None

    def _validate(self) -> None:
        if self.tsig is None and self.subnets is None:
            raise ValueError("'subnets' or 'rsig' must be configured")
