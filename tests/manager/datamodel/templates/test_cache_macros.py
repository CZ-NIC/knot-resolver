from typing import Any

import pytest

from knot_resolver_manager.datamodel.cache_schema import CacheClearRPCSchema
from knot_resolver_manager.datamodel.templates import template_from_str


@pytest.mark.parametrize(
    "val,res",
    [
        ({}, "cache.clear(nil,false,nil,100)"),
        ({"chunk-size": 200}, "cache.clear(nil,false,nil,200)"),
        ({"name": "example.com.", "exact-name": True}, "cache.clear('example.com.',true,nil,nil)"),
        (
            {"name": "example.com.", "exact-name": True, "rr-type": "AAAA"},
            "cache.clear('example.com.',true,kres.type.AAAA,nil)",
        ),
    ],
)
def test_cache_clear(val: Any, res: Any):
    tmpl_str = "{% from 'macros/cache_macros.lua.j2' import cache_clear %}{{ cache_clear(x) }}"

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(x=CacheClearRPCSchema(val)) == res
