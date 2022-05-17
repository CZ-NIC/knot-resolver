from typing import Optional

from knot_resolver_manager.datamodel.types import CheckedPath, InterfacePort
from knot_resolver_manager.utils import SchemaNode


class WebmgmtSchema(SchemaNode):
    """
    Configuration of legacy web management endpoint.

    ---
    unix_socket: Path to unix domain socket to listen to.
    interface: IP address or interface name with port number to listen to.
    tls: Enable/disable TLS.
    cert_file: Path to certificate file.
    key_file: Path to certificate key.
    """

    unix_socket: Optional[CheckedPath] = None
    interface: Optional[InterfacePort] = None
    tls: bool = False
    cert_file: Optional[CheckedPath] = None
    key_file: Optional[CheckedPath] = None

    def _validate(self) -> None:
        if bool(self.unix_socket) == bool(self.interface):
            raise ValueError("One of 'interface' or 'unix-socket' must be configured.")
