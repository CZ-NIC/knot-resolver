from pytest import raises

from knot_resolver_manager.datamodel.server_schema import ManagementSchema
from knot_resolver_manager.exceptions import KresdManagerException


def test_management_watchdog():
    assert ManagementSchema({"watchdog": {"qname": "nic.cz.", "qtype": "A"}})

    with raises(KresdManagerException):
        ManagementSchema({"backend": "supervisord", "watchdog": {"qname": "nic.cz.", "qtype": "A"}})
