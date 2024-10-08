from typing import Optional

from knot_resolver.datamodel.types import IPAddressPort, WritableFilePath
from knot_resolver.utils.modeling import ConfigSchema


class ManagementSchema(ConfigSchema):
    """
    Configuration of management HTTP API.

    ---
    unix_socket: Path to unix domain socket to listen to.
    interface: IP address and port number to listen to.
    """

    unix_socket: Optional[WritableFilePath] = None
    interface: Optional[IPAddressPort] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")
