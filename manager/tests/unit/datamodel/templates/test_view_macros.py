from typing import Any

import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.view_schema import ViewOptionsSchema, ViewSchema


def test_view_insert_action():
    subnet = "10.0.0.0/8"
    action = "policy.DENY"
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_insert_action %}
{{ view_insert_action(subnet, action) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(subnet=subnet, action=action) == f"assert(C.kr_view_insert_action('{ subnet }',{ action })==0)"


def test_view_options_flags():
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_options_flags %}
{{ view_options_flags(options) }}"""

    tmpl = template_from_str(tmpl_str)
    options = ViewOptionsSchema({"dns64": False, "minimize": False})
    assert tmpl.render(options=options) == "policy.FLAGS({'NO_MINIMIZE','DNS64_DISABLE',})"
    assert tmpl.render(options=ViewOptionsSchema()) == "policy.FLAGS({})"


def test_view_answer():
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_options_flags %}
{{ view_options_flags(options) }}"""

    tmpl = template_from_str(tmpl_str)
    options = ViewOptionsSchema({"dns64": False, "minimize": False})
    assert tmpl.render(options=options) == "policy.FLAGS({'NO_MINIMIZE','DNS64_DISABLE',})"
    assert tmpl.render(options=ViewOptionsSchema()) == "policy.FLAGS({})"


@pytest.mark.parametrize(
    "val,res",
    [
        ("allow", "policy.TAGS_ASSIGN({})"),
        ("refused", "policy.REFUSE"),
        ("noanswer", "policy.NO_ANSWER"),
    ],
)
def test_view_answer(val: Any, res: Any):
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_answer %}
{{ view_answer(view.answer) }}"""

    tmpl = template_from_str(tmpl_str)
    view = ViewSchema({"subnets": "10.0.0.0/8", "answer": val})
    assert tmpl.render(view=view) == res
