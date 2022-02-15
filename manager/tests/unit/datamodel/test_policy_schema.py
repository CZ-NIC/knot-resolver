from pytest import raises

from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.exceptions import KresManagerException


def test_simple_actions():
    assert PolicySchema({"action": "pass"})
    assert PolicySchema({"action": "deny"})
    assert PolicySchema({"action": "drop"})
    assert PolicySchema({"action": "refuse"})
    assert PolicySchema({"action": "tc"})
    assert PolicySchema({"action": "debug-always"})
    assert PolicySchema({"action": "debug-cache-miss"})
    assert PolicySchema({"action": "qtrace"})
    assert PolicySchema({"action": "reqtrace"})

    with raises(KresManagerException):
        PolicySchema({"action": "invalid-action"})


def test_deny_message():
    assert PolicySchema({"action": "deny", "message": "this is deny message"})

    with raises(KresManagerException):
        PolicySchema({"action": "pass", "message": "this is deny message"})


def test_reroute():
    assert PolicySchema({"action": "reroute", "reroute": [{"source": "192.0.2.0/24", "destination": "127.0.0.0"}]})

    with raises(KresManagerException):
        PolicySchema({"action": "reroute"})
    with raises(KresManagerException):
        PolicySchema({"action": "pass", "reroute": [{"source": "192.0.2.0/24", "destination": "127.0.0.0"}]})


def test_answer():
    assert PolicySchema({"action": "answer", "answer": {"rtype": "AAAA", "rdata": "::1"}})

    with raises(KresManagerException):
        PolicySchema({"action": "answer"})
    with raises(KresManagerException):
        PolicySchema({"action": "pass", "answer": {"rtype": "AAAA", "rdata": "::1"}})


def test_mirror():
    assert PolicySchema({"action": "mirror", "mirror": ["127.0.0.1@5353"]})

    with raises(KresManagerException):
        PolicySchema({"action": "mirror"})
    with raises(KresManagerException):
        PolicySchema({"action": "pass", "mirror": ["127.0.0.1@5353"]})
