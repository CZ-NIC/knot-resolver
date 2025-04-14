from typing import List, Optional

from knot_resolver.datamodel.types import IPv6Network, IPv6Network96, TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class Dns64Schema(ConfigSchema):
    """
    DNS64 (RFC 6147) configuration.

    ---
    enabled: Enable/disable DNS64.
    prefix: IPv6 prefix to be used for synthesizing AAAA records.
    reverse_ttl: TTL in CNAME generated in the reverse 'ip6.arpa.' subtree.
    exclude_subnets: IPv6 subnets that are disallowed in answer.
    """

    enabled: bool = False
    prefix: IPv6Network96 = IPv6Network96("64:ff9b::/96")
    reverse_ttl: Optional[TimeUnit] = None
    exclude_subnets: Optional[List[IPv6Network]] = None
