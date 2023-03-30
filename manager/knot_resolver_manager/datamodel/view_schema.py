from typing import List, Optional, Union
from typing_extensions import Literal
from knot_resolver_manager.utils.modeling import ConfigSchema
from knot_resolver_manager.datamodel.types import IDPattern, IPNetwork


class ViewOptionsSchema(ConfigSchema):
    """
    Configuration options for clients identified by the view.

    ---
    minimize: Send minimum amount of information in recursive queries to enhance privacy.
    dns64: Enable/disable DNS64.
    """

    minimize: bool = True
    dns64: bool = True


class ViewSchema(ConfigSchema):
    """
    Configuration parameters that allow you to create personalized policy rules and other.

    ---
    subnets: Identifies the client based on his subnet.
    tsig: Identifies the client based on a TSIG key name (for testing purposes, TSIG signature is not verified!).
    options: Configuration options for clients identified by the view.
    answer: Direct approach how to handle request from clients identified by the view.
    tags: Tags to link with other policy rules.
    """

    subnets: Optional[Union[List[IPNetwork], IPNetwork]] = None
    tsig: Optional[List[str]] = None
    tags: Optional[List[IDPattern]] = None
    answer: Optional[Literal["allow", "refused"]] = None
    options: ViewOptionsSchema = ViewOptionsSchema()

    def _validate(self) -> None:
        if self.tsig is None and self.subnets is None:
            raise ValueError("'subnets' or 'rsig' must be configured")
