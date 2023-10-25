from typing import Any, List

import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.view_schema import ViewOptionsSchema, ViewSchema


@pytest.mark.parametrize(
    "val,lua",
    [
        (None, "0"),
        (
            ["udp53", "tcp53", "dot", "doh", "doq"],
            "0 + 2^C.KR_PROTO_UDP53 + 2^C.KR_PROTO_TCP53 + 2^C.KR_PROTO_DOT + 2^C.KR_PROTO_DOH + 2^C.KR_PROTO_DOQ",
        ),
    ],
)
def test_view_protocols(val, lua):
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_protocols %}
{{ view_protocols(protocols) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(protocols=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        (ViewOptionsSchema({"dns64": False, "minimize": False}), '"NO_MINIMIZE",\n"DNS64_DISABLE",\n'),
        (ViewOptionsSchema({"minimize": False}), '"NO_MINIMIZE",\n'),
        (ViewOptionsSchema({"dns64": False}), '"DNS64_DISABLE",\n'),
        (ViewOptionsSchema(), ""),
    ],
)
def test_view_options(val, lua):
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_options_flags %}
{{ view_options_flags(options) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(options=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        ("allow", "policy.TAGS_ASSIGN({})"),
        ("refused", "'policy.REFUSE'"),
        ("noanswer", "'policy.NO_ANSWER'"),
    ],
)
def test_view_answer(val, lua):
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_answer %}
{{ view_answer(view.answer) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(view=ViewSchema({"subnets": ["10.0.0.0/8"], "answer": val})) == lua
