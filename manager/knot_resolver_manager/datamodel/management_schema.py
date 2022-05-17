from typing import Optional

from knot_resolver_manager.datamodel.types import CheckedPath, IPAddressPort
from knot_resolver_manager.utils import SchemaNode


class ManagementSchema(SchemaNode):
    """
    Configuration of management HTTP API.

    ---
    unix_socket: Path to unix domain socket to listen to.
    interface: IP address and port number to listen to.
    """

    unix_socket: Optional[CheckedPath] = None
    interface: Optional[IPAddressPort] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")
