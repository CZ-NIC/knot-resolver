from typing import Any, Dict, Optional

import pytest

from knot_resolver_manager.datamodel.server_schema import ManagementSchema, ServerSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_watchdog_backend_invalid():
    with pytest.raises(KresManagerException):
        ServerSchema({"backend": "supervisord", "watchdog": {"qname": "nic.cz.", "qtype": "A"}})


@pytest.mark.parametrize("val", [{"interface": "::1@53"}, {"unix-socket": "/path/socket"}])
def test_management_valid(val: Dict[str, Any]):
    o = ManagementSchema(val)
    if o.interface:
        assert str(o.interface) == val["interface"]
    if o.unix_socket:
        assert str(o.unix_socket) == val["unix-socket"]


@pytest.mark.parametrize("val", [None, {"interface": "::1@53", "unix-socket": "/path/socket"}])
def test_management_invalid(val: Optional[Dict[str, Any]]):
    with pytest.raises(KresManagerException):
        ManagementSchema(val)
