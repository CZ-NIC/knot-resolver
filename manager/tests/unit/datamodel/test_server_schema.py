from pytest import raises

from knot_resolver_manager.datamodel.server_schema import ServerSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_watchdog():
    assert ServerSchema({"watchdog": {"qname": "nic.cz.", "qtype": "A"}})

    with raises(KresManagerException):
        ServerSchema({"backend": "supervisord", "watchdog": {"qname": "nic.cz.", "qtype": "A"}})
