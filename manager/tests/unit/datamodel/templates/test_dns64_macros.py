import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.dns64_schema import Dns64Schema


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            Dns64Schema({"prefix": "64:ff9b::/96"}),
            """dns64.config({
    prefix = '64:ff9b::',
})""",
        ),
        (
            Dns64Schema({"prefix": "64:ff9b::/96", "rev-ttl": "5s", "exclude-subnets": ["2001:db8:888::/48"]}),
            """dns64.config({
    prefix = '64:ff9b::',
    rev_ttl = 5,
    exclude_subnets = {'2001:db8:888::/48',},
})""",
        ),
        (
            Dns64Schema({"prefix": "64:ff9b::/96", "rev-ttl": "1m", "exclude-subnets": ["2001:db8:888::/48", "::/0"]}),
            """dns64.config({
    prefix = '64:ff9b::',
    rev_ttl = 60,
    exclude_subnets = {'2001:db8:888::/48','::/0',},
})""",
        ),
    ],
)
def test_dns64_config(val, lua):
    tmpl = template_from_str("{% from 'macros/dns64_macros.lua.j2' import dns64_config %}{{ dns64_config(config) }}")
    assert tmpl.render(config=val) == lua
