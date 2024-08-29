from typing import Literal, Union

from knot_resolver.datamodel.types import DomainName, EscapedStr, IPAddress, PortNumber, TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class GraphiteSchema(ConfigSchema):
    host: Union[IPAddress, DomainName]
    port: PortNumber = PortNumber(2003)
    prefix: EscapedStr = EscapedStr("")
    interval: TimeUnit = TimeUnit("5s")
    tcp: bool = False


class MonitoringSchema(ConfigSchema):
    """
    ---
    enabled: configures, whether statistics module will be loaded into resolver
    graphite: optionally configures where should graphite metrics be sent to
    """

    enabled: Literal["manager-only", "lazy", "always"] = "lazy"
    graphite: Union[Literal[False], GraphiteSchema] = False
