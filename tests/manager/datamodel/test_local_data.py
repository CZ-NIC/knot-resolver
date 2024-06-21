from typing import Any

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.local_data_schema import RuleSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError


@pytest.mark.parametrize(
    "val",
    [
        {"name": ["sub2.example.org"], "subtree": "empty", "tags": ["t01"]},
        {"name": ["sub3.example.org", "sub5.example.net."], "subtree": "nxdomain", "ttl": "1h"},
        {"name": ["sub4.example.org"], "subtree": "redirect"},
        {"name": ["sub5.example.org"], "address": ["127.0.0.1"]},
        {"name": ["sub6.example.org"], "subtree": "redirect", "address": ["127.0.0.1"]},
        {"file": "/etc/hosts", "ttl": "20m", "nodata": True},
        {"records": "", "ttl": "20m", "nodata": True},
    ],
)
def test_subtree_valid(val: Any):
    RuleSchema(val)


@pytest.mark.parametrize(
    "val",
    [
        {"subtree": "empty"},
        {"name": ["sub2.example.org"], "file": "/etc/hosts"},
        {"name": ["sub4.example.org"], "address": ["127.0.0.1"], "subtree": "nxdomain"},
        {"name": ["sub4.example.org"], "subtree": "redirect", "file": "/etc/hosts"},
    ],
)
def test_subtree_invalid(val: Any):
    with raises(DataValidationError):
        RuleSchema(val)
