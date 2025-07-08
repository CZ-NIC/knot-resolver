from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel.types import (
    EscapedStr,
    IPAddressOptionalPort,
)
from knot_resolver.utils.modeling import ConfigSchema


class KafkaSchema(ConfigSchema):
    """
    Configuration of Apache Kafka client.  Requires the optional 'kafka-python' dependency.
    ---
    enable: Enable/disable Kafka client.
    topic: Topic to subscribe data from.
    server: Kafka server to connect.
    """

    enable: bool = False
    topic: EscapedStr = EscapedStr("knot-resolver")
    server: IPAddressOptionalPort = IPAddressOptionalPort("127.0.0.1@9092")

    def _validate(self) -> None:
        if self.enable and not KAFKA_LIB:
            raise ValueError(
                "'kafka' is enabled, but the required 'kafka-python' dependency (optional) is not installed"
            )
