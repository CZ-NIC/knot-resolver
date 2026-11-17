import pytest
from pytest import raises

from knot_resolver.datamodel.forward_schema import ForwardSchema
from knot_resolver.utils.modeling.exceptions import DataValidationError


@pytest.mark.parametrize("port,auth", [(5335, False), (53, True)])
def test_forward_valid(port: int, auth: bool):
    assert ForwardSchema(
        {"subtree": ".", "options": {"authoritative": auth, "dnssec": True}, "servers": [f"127.0.0.1", "::1"]}
    )
    assert ForwardSchema(
        {"subtree": ".", "options": {"authoritative": auth, "dnssec": False}, "servers": [f"127.0.0.1@{port}", "::1"]}
    )

    assert ForwardSchema(
        {
            "subtree": ".",
            "options": {"authoritative": auth, "dnssec": False},
            "servers": [{"address": [f"127.0.0.1@{port}", "::1"]}],
        }
    )

    assert ForwardSchema(
        {
            "subtree": ".",
            "options": {"authoritative": auth, "dnssec": False},
            "servers": [{"address": [f"127.0.0.1", "::1"]}],
        }
    )


@pytest.mark.parametrize("tcp", [False, True])
def test_forward_tcp(tcp: bool):
    fwd = ForwardSchema({"subtree": ".", "options": {"tcp": tcp}, "servers": ["127.0.0.1"]})
    assert fwd.options.tcp == tcp
    assert ForwardSchema({"subtree": ".", "servers": ["127.0.0.1"]}).options.tcp is False


@pytest.mark.parametrize(
    "port,auth,tls",
    [(5335, True, False), (53, True, True)],
)
def test_forward_invalid(port: int, auth: bool, tls: bool):
    if not tls:
        with raises(DataValidationError):
            ForwardSchema(
                {
                    "subtree": ".",
                    "options": {"authoritative": auth, "dnssec": False},
                    "servers": [f"127.0.0.1@{port}", "::1"],
                }
            )

    with raises(DataValidationError):
        ForwardSchema(
            {
                "subtree": ".",
                "options": {"authoritative": auth, "dnssec": False},
                "servers": [{"address": [f"127.0.0.1{port}", f"::1{port}"], "transport": "tls" if tls else None}],
            }
        )
