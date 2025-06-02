from typing import Literal, Union

from knot_resolver.datamodel.types import DomainName, EscapedStr, IPAddress, PortNumber, TimeUnit
from knot_resolver.utils.modeling import ConfigSchema


class GraphiteSchema(ConfigSchema):
    enable: bool = False
    host: Union[None, IPAddress, DomainName] = None
    port: PortNumber = PortNumber(2003)
    prefix: EscapedStr = EscapedStr("")
    interval: TimeUnit = TimeUnit("5s")
    tcp: bool = False

    def _validate(self) -> None:
        if self.enable and not self.host:
            raise ValueError("'host' option must be configured to enable graphite bridge")


class MonitoringSchema(ConfigSchema):
    """
    ---
    metrics: configures, whether metrics/statistics will be collected by the resolver
    graphite: optionally configures where should graphite metrics be sent to
    """

    metrics: Literal["manager-only", "lazy", "always"] = "lazy"
    graphite: GraphiteSchema = GraphiteSchema()
