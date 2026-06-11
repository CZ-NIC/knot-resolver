from typing import Literal, Optional, Union

from knot_resolver.constants import KAFKA_LIB
from knot_resolver.datamodel.types import (
    DomainNameOptionalPort,
    EscapedStr,
    IPAddressOptionalPort,
    ListOrItem,
    ReadableFile,
)
from knot_resolver.utils.modeling import ConfigSchema


class KafkaSchema(ConfigSchema):
    """
    Configuration of Apache Kafka client.  Requires the optional 'kafka-python' dependency.

    ---
    enable: Enable/disable Kafka client.
    topic: Topic to subscribe data from.
    server: Kafka server(s) to connect.
    group_id: Optional, Kafka consumer group identifier.
    zone_id: Identifier for determining the recipient(s) using a the key (zone-id) of the Kafka message.
    security_protocol: Protocol used to communicate with server(broker).
    cert_file: Optional, the client's certificate file in PEM format.
    key_file: Optional, the client's private key file.
    ca_file: Optional, CA file to use in certificate verification.
    """

    enable: bool = False
    topic: EscapedStr = EscapedStr("knot-resolver")
    server: ListOrItem[Union[IPAddressOptionalPort, DomainNameOptionalPort]] = ListOrItem(
        DomainNameOptionalPort("localhost@9092")
    )
    group_id: Optional[EscapedStr] = None
    zone_id: Optional[EscapedStr] = None
    security_protocol: Literal["plaintext", "ssl"] = "plaintext"
    cert_file: Optional[ReadableFile] = None
    key_file: Optional[ReadableFile] = None
    ca_file: Optional[ReadableFile] = None

    def _validate(self) -> None:
        if self.enable and not KAFKA_LIB:
            raise ValueError(
                "'kafka' is enabled, but the required 'kafka-python' dependency (optional) is not installed"
            )
        if self.enable and not self.zone_id:
            raise ValueError("'zone-id' option is required for enabled Kafka client")
