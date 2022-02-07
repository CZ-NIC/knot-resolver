from typing import Optional

from typing_extensions import Literal

from knot_resolver_manager.utils.modelling import SchemaNode


class GraphiteSchema(SchemaNode):
    endpoint: str
    prefix: str
    interval_sec: int
    tcp: bool


class MonitoringSchema(SchemaNode):
    """
    ---
    state: configures, whether statistics module will be loaded into resolver
    graphite: optionally configures where should graphite metrics be sent to
    """

    state: Literal["manager-only", "lazy", "always"] = "always"
    graphite: Optional[GraphiteSchema] = None
