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
    tags: Tags to link with other policy rules.
    options: Configuration options for clients identified by the view.
    answer: Direct approach how to handle request from clients identified by the view.
    """

    subnets: Optional[Union[List[IPNetwork], IPNetwork]] = None
    tags: Optional[List[IDPattern]] = None
    options: ViewOptionsSchema = ViewOptionsSchema()
    answer: Optional[Literal["allow", "refused"]] = None
