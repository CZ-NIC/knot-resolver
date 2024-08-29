from typing import List, Literal, Optional

from knot_resolver.datamodel.policy_schema import ActionSchema
from knot_resolver.utils.modeling import ConfigSchema


class SliceSchema(ConfigSchema):
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
