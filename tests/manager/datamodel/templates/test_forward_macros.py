from knot_resolver.datamodel.forward_schema import ForwardSchema
from knot_resolver.datamodel.templates import template_from_str
from knot_resolver.datamodel.types import IPAddressOptionalPort


def test_policy_rule_forward_add():
    tmpl_str = """{% from 'macros/forward_macros.lua.j2' import policy_rule_forward_add %}
{{ policy_rule_forward_add(rule.subtree[0],rule.options,rule.servers) }}"""

    rule = ForwardSchema(
        {
            "subtree": ".",
            "servers": [{"address": ["2001:148f:fffe::1", "185.43.135.1"], "hostname": "odvr.nic.cz"}],
            "options": {
                "authoritative": False,
                "dnssec": True,
            },
        }
    )
    result = "policy.rule_forward_add('.',{dnssec=true,auth=false},{{'2001:148f:fffe::1',tls=false,insecure=false,hostname='odvr.nic.cz',},{'185.43.135.1',tls=false,insecure=false,hostname='odvr.nic.cz',},})"

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(rule=rule) == result

    rule.servers = [IPAddressOptionalPort("2001:148f:fffe::1"), IPAddressOptionalPort("185.43.135.1")]
    result = "policy.rule_forward_add('.',{dnssec=true,auth=false},{{'2001:148f:fffe::1'},{'185.43.135.1'},})"
    assert tmpl.render(rule=rule) == result
