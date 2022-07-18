from knot_resolver_manager.datamodel.types import IPv6Network96
from knot_resolver_manager.utils.modeling import BaseSchema


class Dns64Schema(BaseSchema):
    """
    DNS64 (RFC 6147) configuration.

    ---
    prefix: IPv6 prefix to be used for synthesizing AAAA records.
    """

    prefix: IPv6Network96 = IPv6Network96("64:ff9b::/96")
