from typing import List, Optional

from typing_extensions import Literal

from knot_resolver_manager.datamodel.policy_schema import ActionSchema
from knot_resolver_manager.utils import SchemaNode


class SliceSchema(SchemaNode):
    """
    Split the entire DNS namespace into distinct slices.

    ---
    function: Slicing function that returns index based on query
    views: Use this Slice only for clients defined by views.
    actions: Actions for slice.
    """

    function: Literal["randomize-psl"] = "randomize-psl"
    views: Optional[List[str]] = None
    actions: List[ActionSchema]
