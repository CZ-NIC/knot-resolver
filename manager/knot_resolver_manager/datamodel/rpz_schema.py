from typing import List, Optional

from knot_resolver_manager.datamodel.policy_schema import ActionEnum
from knot_resolver_manager.datamodel.types import AnyPath
from knot_resolver_manager.datamodel.view_schema import FlagsEnum
from knot_resolver_manager.utils import SchemaNode


class RPZSchema(SchemaNode):
    action: ActionEnum
    file: AnyPath
    watch: bool = True
    message: Optional[str] = None
    views: Optional[str] = None
    options: Optional[List[FlagsEnum]] = None
