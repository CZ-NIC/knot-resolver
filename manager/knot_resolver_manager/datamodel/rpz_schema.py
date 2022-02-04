from typing import List, Optional

from knot_resolver_manager.datamodel.types import CheckedPath, PolicyActionEnum, PolicyFlagEnum
from knot_resolver_manager.utils import SchemaNode


class RPZSchema(SchemaNode):
    """
    Configuration or Response Policy Zone (RPZ).

    ---
    action: RPZ rule action, typically 'deny'.
    file: Path to the RPZ zone file.
    watch: Reload the file when it changes.
    views: Use RPZ rule only for clients defined by views.
    options: Configuration flags for RPZ rule.
    message: Deny message for 'deny' action.
    """

    action: PolicyActionEnum
    file: CheckedPath
    watch: bool = True
    views: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None
    message: Optional[str] = None

    def _validate(self) -> None:
        if self.message and not self.action == "deny":
            raise ValueError("'message' field can only be defined for 'deny' action")
