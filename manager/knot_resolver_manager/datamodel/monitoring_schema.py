from typing import Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import TimeUnit
from knot_resolver_manager.utils.modelling import SchemaNode


class GraphiteSchema(SchemaNode):
    host: str
    port: int = 2003
    prefix: str = ""
    interval_sec: TimeUnit = TimeUnit("5s")
    tcp: bool = False

    def _validate(self):
        if not 0 < self.port < 65_536:
            raise ValueError("port must be between 0 and 65536 (both exclusive)")


class MonitoringSchema(SchemaNode):
    """
    ---
    enabled: configures, whether statistics module will be loaded into resolver
    graphite: optionally configures where should graphite metrics be sent to
    """

    enabled: Literal["manager-only", "lazy", "always"] = "lazy"
    graphite: Union[Literal[False], GraphiteSchema] = False
