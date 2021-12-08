from typing import List, Optional

from knot_resolver_manager.datamodel.policy_schema import ActionEnum
from knot_resolver_manager.datamodel.types import AnyPath
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode


class RPZSchema(SchemaNode):
    action: ActionEnum
    file: AnyPath
    watch: bool = True
    views: Optional[List[str]] = None
    options: Optional[List[FlagsEnum]] = None
    message: Optional[str] = None

    def _validate(self) -> None:
        if self.message and not self.action == "deny":
            raise ValueError("'message' field can only be defined for 'deny' action")
