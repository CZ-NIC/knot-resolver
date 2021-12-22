from typing import List, Optional

from knot_resolver_manager.datamodel.network_schema import AddressRenumberingSchema
from knot_resolver_manager.datamodel.types import ActionEnum, FlagsEnum, IPAddressPort, RecordTypeEnum, TimeUnit
from knot_resolver_manager.utils import SchemaNode


class FilterSchema(SchemaNode):
    suffix: Optional[str] = None
    pattern: Optional[str] = None
    qtype: Optional[RecordTypeEnum] = None


class AnswerSchema(SchemaNode):
    qtype: RecordTypeEnum
    rdata: str
    ttl: TimeUnit = TimeUnit("1s")
    nodata: bool = False


class PolicySchema(SchemaNode):
    action: ActionEnum
    order: Optional[int] = None
    filter: Optional[FilterSchema] = None
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
    message: Optional[str] = None
    reroute: Optional[List[AddressRenumberingSchema]] = None
    answer: Optional[AnswerSchema] = None
    mirror: Optional[List[IPAddressPort]] = None

    def _validate(self) -> None:
        # checking for missing fields
        if self.action == "reroute" and not self.reroute:
            raise ValueError("missing mandatory field 'reroute' for 'reroute' action")
        if self.action == "answer" and not self.answer:
            raise ValueError("missing mandatory field 'answer' for 'answer' action")
        if self.action == "mirror" and not self.mirror:
            raise ValueError("missing mandatory field 'mirror' for 'mirror' action")

        # checking for unnecessary fields
        if self.message and not self.action == "deny":
            raise ValueError("'message' field can only be defined for 'deny' action")
        if self.reroute and not self.action == "reroute":
            raise ValueError("'answer' field can only be defined for 'answer' action")
        if self.answer and not self.action == "answer":
            raise ValueError("'answer' field can only be defined for 'answer' action")
        if self.mirror and not self.action == "mirror":
            raise ValueError("'mirror' field can only be defined for 'mirror' action")
