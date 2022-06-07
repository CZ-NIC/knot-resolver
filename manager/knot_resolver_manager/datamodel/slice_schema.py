from typing import List, Optional

from typing_extensions import Literal

from knot_resolver_manager.utils import SchemaNode

SlicingFunctionEnum = Literal["randomize-psl"]


class SliceSchema(SchemaNode):
    """
    Split the entire DNS namespace into distinct slices.

    ---
    function: Slicing function that returns index based on query
    views: Use this Slice only for clients defined by views.
    """

    function: SlicingFunctionEnum = "randomize-psl"
    views: Optional[List[str]] = None
