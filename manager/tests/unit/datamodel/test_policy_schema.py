from typing import Any, Dict

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.exceptions import KresManagerException


@pytest.mark.parametrize("val", [{"action": "invalid-action"}])
def test_simple_actions_invalid(val: Dict[str, Any]):
    with raises(KresManagerException):
        PolicySchema({"action": "invalid-action"})


@pytest.mark.parametrize(
    "val",
    [
        "pass",
        "drop",
        "refuse",
        "tc",
        "debug-always",
        "debug-cache-miss",
        "qtrace",
        "reqtrace",
    ],
)
def test_message_invalid(val: str):
    with raises(KresManagerException):
        PolicySchema({"action": f"{val}", "message": "this is deny message"})


@pytest.mark.parametrize(
    "val",
    [
        {"action": "reroute"},
        {"action": "answer"},
        {"action": "mirror"},
        {"action": "pass", "reroute": [{"source": "192.0.2.0/24", "destination": "127.0.0.0"}]},
        {"action": "pass", "answer": {"rtype": "AAAA", "rdata": "::1"}},
        {"action": "pass", "mirror": ["127.0.0.1@5353"]},
    ],
)
def test_invalid(val: Dict[str, Any]):
    with raises(KresManagerException):
        PolicySchema(val)
