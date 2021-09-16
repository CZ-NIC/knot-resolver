from knot_resolver_manager.datamodel.types import IPv6Network96
from knot_resolver_manager.utils import SchemaNode


class Dns64(SchemaNode):
    prefix: IPv6Network96 = IPv6Network96("64:ff9b::/96")


class Dns64Strict(SchemaNode):
    prefix: IPv6Network96
