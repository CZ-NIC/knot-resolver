from typing import List, Optional, Union

from knot_resolver_manager.datamodel.network_schema import AddressRenumberingSchema
from knot_resolver_manager.datamodel.types import (
    CheckedPath,
    DNSRecordTypeEnum,
    DomainName,
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
    """
    Configuration of Forward server.

    ---
    address: IP address of Forward server.
    pin_sha256: Hash of accepted CA certificate.
    hostname: Hostname of the Forward server.
    ca_file: Path to CA certificate file.
    """

    address: IPAddressOptionalPort
    pin_sha256: Optional[Union[str, List[str]]] = None
    hostname: Optional[DomainName] = None
    ca_file: Optional[CheckedPath] = None


def _validate_policy_action(policy_action: Union["ActionSchema", "PolicySchema"]) -> None:
    servers = ["mirror", "forward", "stub"]

    def _field(ac: str) -> str:
        if ac in servers:
            return "servers"
        return {"deny": "message"}.get(ac, ac)

    configurable_actions = ["deny", "reroute", "answer"] + servers

    # checking for missing mandatory fields for actions
    field = _field(policy_action.action)
    if policy_action.action in configurable_actions and not getattr(policy_action, field):
        raise ValueError(f"missing mandatory field '{field}' for '{policy_action.action}' action")

    # checking for unnecessary fields
    for ac in configurable_actions + ["deny"]:
        field = _field(ac)
        if getattr(policy_action, field) and _field(policy_action.action) != field:
            raise ValueError(f"'{field}' field can only be defined for '{ac}' action")

    # ForwardServerSchema is valid only for 'forward' action
    if policy_action.servers:
        for server in policy_action.servers:  # pylint: disable=not-an-iterable
            if policy_action.action != "forward" and isinstance(server, ForwardServerSchema):
                raise ValueError(
                    f"'ForwardServerSchema' in 'servers' is valid only for 'forward' action, got '{policy_action.action}'"
                )


class ActionSchema(SchemaNode):
    """
    Configuration of policy action.

    ---
    action: Policy action.
    message: Deny message for 'deny' action.
    reroute: Configuration for 'reroute' action.
    answer: Answer definition for 'answer' action.
    servers: Servers configuration for 'mirror', 'forward' and 'stub' action.
    """

    action: PolicyActionEnum
    message: Optional[str] = None
    reroute: Optional[List[AddressRenumberingSchema]] = None
    answer: Optional[AnswerSchema] = None
    servers: Optional[Union[List[IPAddressOptionalPort], List[ForwardServerSchema]]] = None

    def _validate(self) -> None:
        _validate_policy_action(self)


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
    servers: Servers configuration for 'mirror', 'forward' and 'stub' action.
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
        _validate_policy_action(self)
