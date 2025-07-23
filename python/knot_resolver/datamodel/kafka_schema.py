from typing import Literal, Optional

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel.types import (
    EscapedStr,
    IPAddressOptionalPort,
    ReadableFile,
)
from knot_resolver.utils.modeling import ConfigSchema


class KafkaSchema(ConfigSchema):
    """
    Configuration of Apache Kafka client.  Requires the optional 'kafka-python' dependency.
    ---
    enable: Enable/disable Kafka client.
    topic: Topic to subscribe data from.
    server: Kafka server to connect.
    security_protocol: Protocol used to communicate with server(broker).
    cert_file: Optional, the client's certificate file in PEM format.
    key_file: Optional, the client's private key file.
    ca_file: Optional, CA file to use in certificate verification.
    """

    enable: bool = False
    topic: EscapedStr = EscapedStr("knot-resolver")
    server: IPAddressOptionalPort = IPAddressOptionalPort("127.0.0.1@9092")
    security_protocol: Literal["plaintext", "ssl"] = "plaintext"
    cert_file: Optional[ReadableFile] = None
    key_file: Optional[ReadableFile] = None
    ca_file: Optional[ReadableFile] = None

    def _validate(self) -> None:
        if self.enable and not KAFKA_LIB:
            raise ValueError(
                "'kafka' is enabled, but the required 'kafka-python' dependency (optional) is not installed"
            )
