from typing import Union

from typing_extensions import Literal

from knot_resolver_manager.datamodel.types import DNSRecordTypeEnum, DomainName
from knot_resolver_manager.utils import SchemaNode

BackendEnum = Literal["auto", "systemd", "systemd-session", "supervisord"]


class WatchDogSchema(SchemaNode):
    """
    Configuration of systemd watchdog.

    ---
    qname: Name to internaly query for.
    qtype: DNS type to internaly query for.
    """

    qname: DomainName
    qtype: DNSRecordTypeEnum


class SupervisorSchema(SchemaNode):
    """
    Configuration of processes supervisor.

    ---
    backend: Forces the manager to use a specific service supervisor.
    watchdog: Disable systemd watchdog, enable with defaults or set new configuration. Can only be used with 'systemd' backend.
    """

    backend: BackendEnum = "auto"
    watchdog: Union[bool, WatchDogSchema] = True

    def _validate(self) -> None:
        if self.watchdog and self.backend not in ["auto", "systemd", "systemd-session"]:
            raise ValueError("'watchdog' can only be configured for 'systemd' backend")
