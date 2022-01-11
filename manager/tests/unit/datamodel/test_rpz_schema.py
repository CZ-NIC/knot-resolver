from pytest import raises

from knot_resolver_manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_message():

    assert RPZSchema({"action": "deny", "file": "blocklist.rpz", "message": "this is deny message"})

    with raises(KresManagerException):
        RPZSchema({"action": "pass", "file": "whitelist.rpz", "message": "this is deny message"})
