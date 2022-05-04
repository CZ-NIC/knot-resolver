import pytest

from knot_resolver_manager.datamodel.supervisor_schema import SupervisorSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_watchdog_backend_invalid():
    with pytest.raises(KresManagerException):
        SupervisorSchema({"backend": "supervisord", "watchdog": {"qname": "nic.cz.", "qtype": "A"}})
