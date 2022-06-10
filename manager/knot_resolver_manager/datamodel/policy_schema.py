from typing import List, Optional, Union

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


class ForwardServerSchema(SchemaNode):
    pass


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
    servers: Servers configuration for 'mirror', 'forward', 'forward-tls' and 'stub' action.
    """

    action: PolicyActionEnum
    priority: Optional[int] = None
    filter: Optional[FilterSchema] = None
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
    message: Optional[str] = None
    reroute: Optional[List[AddressRenumberingSchema]] = None
    answer: Optional[AnswerSchema] = None
    servers: Optional[Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]] = None

    def _validate(self) -> None:
        servers = ["mirror", "forward", "forward-tls", "stub"]

        def _field(action: str) -> str:
            if action in servers:
                return "servers"
            return {"deny": "message"}.get(action, action)

        configurable_actions = ["deny", "reroute", "answer"] + servers

        # checking for missing mandatory fields for actions
        field = _field(self.action)
        if self.action in configurable_actions and not getattr(self, field):
            raise ValueError(f"missing mandatory field '{field}' for '{self.action}' action")

        # checking for unnecessary fields
        for action in configurable_actions + ["deny"]:
            field = _field(action)
            if getattr(self, field) and _field(self.action) != field:
                raise ValueError(f"'{field}' field can only be defined for '{action}' action")
