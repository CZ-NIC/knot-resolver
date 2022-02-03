from typing import List, Optional

from knot_resolver_manager.datamodel.types import IPNetwork, PolicyFlagEnum
from knot_resolver_manager.utils import SchemaNode


class ViewSchema(SchemaNode):
    """
    Configuration parameters that allow you to create personalized policy rules and other.

    ---
    subnets: Identifies the client based on his subnet.
    tsig: Identifies the client based on a TSIG key name (for testing purposes, TSIG signature is not verified!).
    options: Configuration flags for clients identified by the view.
    """

    subnets: Optional[List[IPNetwork]] = None
    tsig: Optional[List[str]] = None
    options: Optional[List[PolicyFlagEnum]] = None

    def _validate(self) -> None:
        if self.tsig is None and self.subnets is None:
            raise ValueError("'subnets' or 'rsig' must be configured")
