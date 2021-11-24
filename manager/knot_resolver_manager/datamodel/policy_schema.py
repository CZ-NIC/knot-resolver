from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPAddressPort, TimeUnit
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

# TODO: add all other options
ActionEnum = LiteralEnum["pass", "deny", "mirror", "forward", "modify"]


class FilterSchema(SchemaNode):
    suffix: Optional[str] = None
    pattern: Optional[str] = None
    query_type: Optional[str] = None


class AnswerSchema(SchemaNode):
    query_type: str
    rdata: str
    ttl: TimeUnit = TimeUnit("1s")
    no_data: bool = False


class PolicySchema(SchemaNode):
    action: ActionEnum
    filters: Optional[List[FilterSchema]] = None
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
    message: Optional[str] = None
    mirror: Optional[List[IPAddressPort]] = None
    forward: Optional[List[IPAddressPort]] = None
    answer: Optional[AnswerSchema] = None

    def _validate(self) -> None:
        pass
