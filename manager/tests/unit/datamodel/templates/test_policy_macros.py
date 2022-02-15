from typing import List

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.network_schema import AddressRenumberingSchema
from knot_resolver_manager.datamodel.policy_schema import AnswerSchema
from knot_resolver_manager.datamodel.types import PolicyFlagEnum


def test_policy_add():
    rule = "policy.all(policy.DENY)"
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_add %}
{{ policy_add(rule, postrule) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(rule=rule, postrule=False) == f"policy.add({rule})"
    assert tmpl.render(rule=rule, postrule=True) == f"policy.add({rule},true)"


def test_policy_flags():
    flags: List[PolicyFlagEnum] = ["no-cache", "no-edns"]
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_flags %}
{{ policy_flags(flags) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(flags=flags[1]) == f"policy.FLAGS({{'{flags[1].upper().replace('-', '_')}'}})"
    assert (
        tmpl.render(flags=flags) == f"policy.FLAGS({{{str(flags).upper().replace('-', '_').replace(' ', '')[1:-1]},}})"
    )


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
    assert tmpl.render(action=action, suffix=suffix) == f"policy.suffix_common({action},{suffix})"
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
    assert tmpl.render(action=action, path=path) == f"policy.rpz({action},'{path}',false)"
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


def test_policy_answer():
    ans = AnswerSchema({"rtype": "AAAA", "rdata": "192.0.2.7"})
    tmpl_str = """{% from 'macros/policy_macros.lua.j2' import policy_answer %}
{{ policy_answer(ans) }}"""

    tmpl = template_from_str(tmpl_str)
    assert (
        tmpl.render(ans=ans)
        == f"policy.ANSWER({{[kres.type.{ans.rtype}]={{rdata=kres.str2ip('{ans.rdata}'),ttl={ans.ttl.seconds()}}}}},{str(ans.nodata).lower()})"
    )
