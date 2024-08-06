import pytest
from pytest import raises

from knot_resolver_manager.manager.datamodel.rpz_schema import RPZSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError


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
    with raises(DataValidationError):
        RPZSchema({"action": f"{val}", "file": "whitelist.rpz", "message": "this is deny message"})
