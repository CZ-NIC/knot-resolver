from typing import List, Literal, Optional

from knot_resolver.datamodel.types import FloatNonNegative, IDPattern, IPNetwork
from knot_resolver.utils.modeling import ConfigSchema


class ViewOptionsSchema(ConfigSchema):
    """
    Configuration options for clients identified by the view.

    ---
    minimize: Send minimum amount of information in recursive queries to enhance privacy.
    dns64: Enable/disable DNS64.
    price_factor: Multiplies rate-limiting and defer prices of operations, use 0 to whitelist.
    """

    minimize: bool = True
    dns64: bool = True
    price_factor: FloatNonNegative = FloatNonNegative(1.0)


class ViewSchema(ConfigSchema):
    """
    Configuration parameters that allow you to create personalized policy rules and other.

    ---
    subnets: Identifies the client based on his subnet.  Rule with more precise subnet takes priority.
    dst_subnet: Destination subnet, as an additional condition.
    protocols: Transport protocol, as an additional condition.
    tags: Tags to link with other policy rules.
    answer: Direct approach how to handle request from clients identified by the view.
    options: Configuration options for clients identified by the view.
    """

    subnets: List[IPNetwork]
    dst_subnet: Optional[IPNetwork] = None  # could be a list as well, iterated in template
    protocols: Optional[List[Literal["udp53", "tcp53", "dot", "doh", "doq"]]] = None
    tags: Optional[List[IDPattern]] = None
    answer: Optional[Literal["allow", "refused", "noanswer"]] = None
    options: ViewOptionsSchema = ViewOptionsSchema()

    def _validate(self) -> None:
        if bool(self.tags) == bool(self.answer):
            raise ValueError("exactly one of 'tags' and 'answer' must be configured")
