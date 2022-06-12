from typing import Any, Dict

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.policy_schema import PolicySchema
from knot_resolver_manager.datamodel.types import PolicyActionEnum
from knot_resolver_manager.exceptions import KresManagerException
from knot_resolver_manager.utils.types import get_generic_type_arguments

noconfig_actions = [
    "pass",
    "drop",
    "refuse",
    "tc",
    "debug-always",
    "debug-cache-miss",
    "qtrace",
    "reqtrace",
]
configurable_actions = ["deny", "reroute", "answer", "mirror", "forward", "stub"]
policy_actions = get_generic_type_arguments(PolicyActionEnum)


@pytest.mark.parametrize("val", [item for item in policy_actions if item not in configurable_actions])
def test_policy_action_valid(val: Any):
    PolicySchema({"action": val})


@pytest.mark.parametrize("val", [{"action": "invalid-action"}])
def test_action_invalid(val: Dict[str, Any]):
    with raises(KresManagerException):
        PolicySchema(val)


@pytest.mark.parametrize(
    "val",
    [
        {"action": "deny", "message": "this is deny message"},
        {
            "action": "reroute",
            "reroute": [
                {"source": "192.0.2.0/24", "destination": "127.0.0.0"},
                {"source": "10.10.10.0/24", "destination": "192.168.1.0"},
            ],
        },
        {"action": "answer", "answer": {"rtype": "AAAA", "rdata": "192.0.2.7"}},
        {"action": "mirror", "servers": ["192.0.2.1@5353", "2001:148f:ffff::1"]},
        {"action": "forward", "servers": ["192.0.2.1@5353", "2001:148f:ffff::1"]},
        {"action": "stub", "servers": ["192.0.2.1@5353", "2001:148f:ffff::1"]},
    ],
)
def test_policy_valid(val: Dict[str, Any]):
    PolicySchema(val)


@pytest.mark.parametrize(
    "val",
    [
        {"action": "reroute"},
        {"action": "answer"},
        {"action": "mirror"},
        {"action": "pass", "reroute": [{"source": "192.0.2.0/24", "destination": "127.0.0.0"}]},
        {"action": "pass", "answer": {"rtype": "AAAA", "rdata": "::1"}},
        {"action": "pass", "servers": ["127.0.0.1@5353"]},
    ],
)
def test_policy_invalid(val: Dict[str, Any]):
    with raises(KresManagerException):
        PolicySchema(val)


@pytest.mark.parametrize(
    "val",
    noconfig_actions,
)
def test_policy_message_invalid(val: str):
    with raises(KresManagerException):
        PolicySchema({"action": f"{val}", "message": "this is deny message"})
