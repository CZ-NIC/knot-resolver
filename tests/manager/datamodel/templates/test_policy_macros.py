from typing import List

from knot_resolver.datamodel.network_schema import AddressRenumberingSchema
from knot_resolver.datamodel.templates import template_from_str


def test_policy_add():
    rule = "policy.all(policy.DENY)"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_add %}
{{ policy_add(rule, postrule) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(rule=rule, postrule=False) == f"policy.add({rule})"
    assert tmpl.render(rule=rule, postrule=True) == f"policy.add({rule},true)"


def test_policy_tags_assign():
    tags: List[str] = ["t01", "t02", "t03"]
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_tags_assign %}
{{ policy_tags_assign(tags) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(tags=tags[1]) == f"policy.TAGS_ASSIGN('{tags[1]}')"
    assert tmpl.render(tags=tags) == "policy.TAGS_ASSIGN({" + ",".join([f"'{x}'" for x in tags]) + ",})"


def test_policy_get_tagset():
    tags: List[str] = ["t01", "t02", "t03"]
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_get_tagset %}
{{ policy_get_tagset(tags) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(tags=tags[1]) == f"policy.get_tagset('{tags[1]}')"
    assert tmpl.render(tags=tags) == "policy.get_tagset({" + ",".join([f"'{x}'" for x in tags]) + ",})"


# Filters


def test_policy_all():
    action = "policy.DENY"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_all %}
{{ policy_all(action) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(action=action) == f"policy.all({action})"


def test_policy_suffix():
    action = "policy.DROP"
    suffix = "policy.todnames({'example.com'})"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_suffix %}
{{ policy_suffix(action, suffix) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(action=action, suffix=suffix) == f"policy.suffix({action},{suffix})"


def test_policy_suffix_common():
    action = "policy.DROP"
    suffix = "policy.todnames({'first.example.com','second.example.com'})"
    common = "policy.todnames({'example.com'})"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_suffix_common %}
{{ policy_suffix_common(action, suffix, common) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(action=action, suffix=suffix, common=None) == f"policy.suffix_common({action},{suffix})"
    assert (
        tmpl.render(action=action, suffix=suffix, common=common) == f"policy.suffix_common({action},{suffix},{common})"
    )


def test_policy_pattern():
    action = "policy.DENY"
    pattern = "[0-9]+\2cz"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_pattern %}
{{ policy_pattern(action, pattern) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(action=action, pattern=pattern) == f"policy.pattern({action},'{pattern}')"


def test_policy_rpz():
    action = "policy.DENY"
    path = "/etc/knot-resolver/blocklist.rpz"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_rpz %}
{{ policy_rpz(action, path, watch) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(action=action, path=path, watch=False) == f"policy.rpz({action},'{path}',false)"
    assert tmpl.render(action=action, path=path, watch=True) == f"policy.rpz({action},'{path}',true)"


# Non-chain actions


def test_policy_deny_msg():
    msg = "this is deny message"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_deny_msg %}
{{ policy_deny_msg(msg) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(msg=msg) == f"policy.DENY_MSG('{msg}')"


def test_policy_reroute():
    r: List[AddressRenumberingSchema] = [
        AddressRenumberingSchema({"source": "192.0.2.0/24", "destination": "127.0.0.0"}),
        AddressRenumberingSchema({"source": "10.10.10.0/24", "destination": "192.168.1.0"}),
    ]
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_reroute %}
{{ policy_reroute(reroute) }}"""

    tmpl = template_from_str(tmpl_str)
    assert (
        tmpl.render(reroute=r)
        == f"policy.REROUTE({{['{r[0].source}']='{r[0].destination}'}},{{['{r[1].source}']='{r[1].destination}'}},)"
    )
