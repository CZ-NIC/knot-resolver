from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPAddressPort
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.types import LiteralEnum

# TODO: add all other options
ActionEnum = LiteralEnum["deny", "pass", "mirror"]


class FilterSchema(SchemaNode):
    suffix: Optional[str] = None
    pattern: Optional[str] = None
    query_type: Optional[str] = None


class AnswerSchema(SchemaNode):
    pass


class PolicySchema(SchemaNode):
    action: ActionEnum
    mirror: Optional[List[IPAddressPort]] = None
    filters: Optional[List[FilterSchema]] = None
    message: Optional[str] = None
    answer: Optional[AnswerSchema] = None
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None

    def _validate(self) -> None:
        pass
