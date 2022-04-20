import pytest
from pytest import raises

from knot_resolver_manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.exceptions import KresManagerException


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
        RPZSchema({"action": f"{val}", "file": "whitelist.rpz", "message": "this is deny message"})
