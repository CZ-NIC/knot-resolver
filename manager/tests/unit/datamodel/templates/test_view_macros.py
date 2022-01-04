from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.types import IPAddressPort


def test_view_tsig():
    tsig: str = r"\5mykey"
    rule = "policy.all(policy.DENY)"
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_tsig %}
{{ view_tsig(tsig, rule) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(tsig=tsig, rule=rule) == f"view:tsig('{tsig}',{rule})"


def test_view_addr():
    addr: IPAddressPort = IPAddressPort("10.0.0.1")
    rule = "policy.all(policy.DENY)"
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_addr %}
{{ view_addr(addr, rule) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(addr=addr, rule=rule) == f"view:addr('{addr}',{rule})"
