from typing import Any

import pytest
from pytest import raises

from knot_resolver_manager.datamodel.local_data_schema import LocalDataSchema, SubtreeSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError


@pytest.mark.parametrize(
    "val",
    [
        {"type": "empty", "roots": ["sub2.example.org"]},
        {"type": "nxdomain", "roots": ["sub3.example.org", "sub5.example.net."], "ttl": "1h"},
        # {"type": "empty", "roots-url": "https://example.org/blocklist.txt", "refresh": "1d"},
        # {"type": "nxdomain", "roots-file": "/etc/hosts"},  # must be an existing file or validation will fail
        {"type": "redirect", "roots": ["sub4.example.org"]},
    ],
)
def test_subtree_valid(val: Any):
    SubtreeSchema(val)


@pytest.mark.parametrize(
    "val",
    [
        {"type": "empty"},
        {"type": "empty", "roots": ["sub2.example.org"], "roots-url": "https://example.org/blocklist.txt"},
        {"type": "redirect", "roots": ["sub4.example.org"], "refresh": "1d"},
    ],
)
def test_subtree_invalid(val: Any):
    with raises(DataValidationError):
        SubtreeSchema(val)
