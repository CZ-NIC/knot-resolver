from pytest import raises

from knot_resolver_manager.datamodel.server_schema import ManagementSchema, ServerSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_watchdog():
    assert ServerSchema({"watchdog": {"qname": "nic.cz.", "qtype": "A"}})

    with raises(KresManagerException):
        ServerSchema({"backend": "supervisord", "watchdog": {"qname": "nic.cz.", "qtype": "A"}})


def test_management():
    assert ManagementSchema({"interface": "::1@53"})
    assert ManagementSchema({"unix-socket": "/path/socket"})

    with raises(KresManagerException):
        ManagementSchema()
    with raises(KresManagerException):
        ManagementSchema({"ip-address": "::1@53", "unix-socket": "/path/socket"})
