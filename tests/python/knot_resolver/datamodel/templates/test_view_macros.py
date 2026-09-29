from typing import Any

import pytest

from knot_resolver.datamodel.templates import template_from_str
from knot_resolver.datamodel.view_schema import ViewOptionsSchema, ViewSchema
from knot_resolver.utils.modeling.exceptions import DataValidationError


def test_view_flags():
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_flags %}
{{ view_flags(options) }}"""

    tmpl = template_from_str(tmpl_str)
    options = ViewOptionsSchema({"dns64": False, "minimize": False})
    assert tmpl.render(options=options) == '"NO_MINIMIZE","DNS64_DISABLE",'
    assert tmpl.render(options=ViewOptionsSchema()) == ""


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
        ("refused", "'policy.REFUSE'"),
        ("noanswer", "'policy.NO_ANSWER'"),
    ],
)
def test_view_answer(val: Any, res: Any):
    tmpl_str = """{% from 'macros/view_macros.lua.j2' import view_answer %}
{{ view_answer(view.answer) }}"""

    tmpl = template_from_str(tmpl_str)
    view = ViewSchema({"subnets": ["10.0.0.0/8"], "answer": val})
    assert tmpl.render(view=view) == res


# DoH whitelist tests
VIEWS_TMPL = "{% include 'views.lua.j2' %}"


@pytest.fixture
def uuid_file(tmp_path):
    f = tmp_path / "uuids.txt"
    f.write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
    return f


def test_uuid_file_emits_load_call(uuid_file):
    view = ViewSchema({"uuid-file": str(uuid_file), "tags": ["t01"]})
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": [view]})
    assert "C.kr_view_load_uuids(" in out
    assert f"'{uuid_file}'" in out
    assert "policy.TAGS_ASSIGN({'t01',}, {})" in out
    assert "kr_view_insert_action" not in out


def test_subnets_emit_insert_action():
    view = ViewSchema({"subnets": ["10.0.0.0/8", "127.0.0.1"], "answer": "refused"})
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": [view]})
    assert out.count("kr_view_insert_action") == 2
    assert "kr_view_load_uuids" not in out


@pytest.mark.parametrize(
    "cfg",
    [
        {"subnets": ["10.0.0.0/8"]},
        {"subnets": ["10.0.0.0/8"], "tags": ["t"], "answer": "allow"},
    ],
)
def test_tags_answer_exclusive(cfg):
    with pytest.raises((DataValidationError, ValueError)):
        ViewSchema(cfg)


@pytest.mark.parametrize(
    "extra",
    [
        {"answer": "allow"},
        {"subnets": ["10.0.0.0/8"]},
    ],
)
def test_uuid_file_conflicts(tmp_path, extra):
    f = tmp_path / "uuids.txt"
    f.write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
    with pytest.raises((DataValidationError, ValueError)):
        ViewSchema({"uuid-file": str(f), **extra})


def test_uuid_file_without_tags_defaults_to_allow(uuid_file):
    """A uuid-file view with no tags whitelists its UUIDs with no extra policy."""
    view = ViewSchema({"uuid-file": str(uuid_file)})
    assert view.tags is None
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": [view]})
    assert "policy.TAGS_ASSIGN({})" in out


@pytest.mark.parametrize(
    "cfg",
    [
        {"subnets": ["10.0.0.0/8"], "answer": "allow"},
        {"subnets": ["10.0.0.0/8"], "tags": ["t"]},
        {"subnets": ["::1"], "answer": "noanswer", "protocols": ["doq"]},
    ],
)
def test_valid_views(cfg):
    ViewSchema(cfg)


def test_mixed_views(tmp_path):
    f = tmp_path / "u.txt"
    f.write_text("x\n")
    views = [
        ViewSchema({"uuid-file": str(f)}),
        ViewSchema({"subnets": ["10.0.0.0/8"], "answer": "refused"}),
    ]
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": views})
    assert out.count("kr_view_load_uuids") == 1
    assert out.count("kr_view_insert_action") == 1


@pytest.mark.parametrize("views", [None, []])
def test_no_views_renders_nothing(views):
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": views})
    assert "kr_view" not in out


def test_protocols_rendered():
    view = ViewSchema({"subnets": ["10.0.0.0/8"], "answer": "allow", "protocols": ["doq", "dot"]})
    out = template_from_str(VIEWS_TMPL).render(cfg={"views": [view]})
    assert "C.KR_PROTO_DOQ" in out and "C.KR_PROTO_DOT" in out
