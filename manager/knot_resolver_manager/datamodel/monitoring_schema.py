from typing import Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import DomainName, IPAddress, PortNumber, TimeUnit
from knot_resolver_manager.utils.modelling import SchemaNode


class GraphiteSchema(SchemaNode):
    host: Union[IPAddress, DomainName]
    port: PortNumber = PortNumber(2003)
    prefix: str = ""
    interval: TimeUnit = TimeUnit("5s")
    tcp: bool = False


class MonitoringSchema(SchemaNode):
    """
    ---
    enabled: configures, whether statistics module will be loaded into resolver
    graphite: optionally configures where should graphite metrics be sent to
    """

    enabled: Literal["manager-only", "lazy", "always"] = "lazy"
    graphite: Union[Literal[False], GraphiteSchema] = False
