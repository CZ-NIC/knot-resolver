from typing import List, Optional

from knot_resolver_manager.datamodel.network_schema import AddressRenumberingSchema
from knot_resolver_manager.datamodel.types import (
    DNSRecordTypeEnum,
    IPAddressOptionalPort,
    PolicyActionEnum,
    PolicyFlagEnum,
    TimeUnit,
)
from knot_resolver_manager.utils import SchemaNode


class FilterSchema(SchemaNode):
    """
    Query filtering configuration.

    ---
    suffix: Filter based on the suffix of the query name.
    pattern: Filter based on the pattern that match query name.
    qtype: Filter based on the DNS query type.
    """

    suffix: Optional[str] = None
    pattern: Optional[str] = None
    qtype: Optional[DNSRecordTypeEnum] = None


class AnswerSchema(SchemaNode):
    """
    Configuration of custom resource record for DNS answer.

    ---
    rtype: Type of DNS resource record.
    rdata: Data of DNS resource record.
    ttl: Time-to-live value for defined answer.
    nodata: Answer with NODATA If requested type is not configured in the answer. Otherwise policy rule is ignored.
    """

    rtype: DNSRecordTypeEnum
    rdata: str
    ttl: TimeUnit = TimeUnit("1s")
    nodata: bool = False


class PolicySchema(SchemaNode):
    """
    Configuration of policy rule.

    ---
    action: Policy rule action.
    priority: Policy rule priority.
    filter: Query filtering configuration.
    views: Use policy rule only for clients defined by views.
    options: Configuration flags for policy rule.
    message: Deny message for 'deny' action.
    reroute: Configuration for 'reroute' action.
    answer: Answer definition for 'answer' action.
    mirror: Mirroring parameters for 'mirror' action.
    """

    action: PolicyActionEnum
    priority: Optional[int] = None
    filter: Optional[FilterSchema] = None
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
    message: Optional[str] = None
    reroute: Optional[List[AddressRenumberingSchema]] = None
    answer: Optional[AnswerSchema] = None
    mirror: Optional[List[IPAddressOptionalPort]] = None

    def _validate(self) -> None:
        # checking for missing mandatory fields for actions
        mandatory_fields = ["reroute", "answer", "mirror"]
        if self.action in mandatory_fields and not getattr(self, self.action):
            raise ValueError(f"missing mandatory field '{self.action}' for '{self.action}' action")

        # checking for unnecessary fields
        for action in ["deny"] + mandatory_fields:
            field = {"deny": "message"}.get(action, action)
            if getattr(self, field) and not self.action == action:
                raise ValueError(f"'{field}' field can only be defined for '{self.action}' action")
