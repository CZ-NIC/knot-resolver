from knot_resolver_manager.datamodel.types import DNSRecordTypeEnum, DomainName
from knot_resolver_manager.utils import SchemaNode


class WatchDogSchema(SchemaNode):
    """
    Configuration of supervisord's watchdog which tests whether the started worker is working correctly.

    ---
    qname: Name to internaly query for.
    qtype: DNS type to internaly query for.
    """

    qname: DomainName
    qtype: DNSRecordTypeEnum
