import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.forward_schema import ForwardServerSchema


@pytest.mark.parametrize(
    "val",
    ["string", 55, 5.5, True, None],
)
def test_quotes(val):
    tmpl = template_from_str("{% from 'macros/common_macros.lua.j2' import quotes %}{{ quotes(string) }}")
    assert tmpl.render(string=val) == f"'{val}'"


@pytest.mark.parametrize(
    "val,lua",
    [(True, "true"), (False, "false"), (1, "true"), (0, "false")],
)
def test_boolean(val, lua):
    tmpl = template_from_str("{% from 'macros/common_macros.lua.j2' import boolean %}{{ boolean(bool, negation) }}")
    assert tmpl.render(bool=val, negation=False) == lua
    assert tmpl.render(bool=not bool(val), negation=True) == lua


# MODULES


@pytest.mark.parametrize(
    "val",
    ["module_name_to_load"],
)
def test_modules_load(val):
    tmpl = template_from_str(
        "{% from 'macros/common_macros.lua.j2' import modules_load %}{{ modules_load(module_name) }}"
    )
    assert tmpl.render(module_name=val) == f"modules.load('{val}')"


@pytest.mark.parametrize(
    "val",
    ["module_name_to_unload"],
)
def test_modules_unload(val):
    tmpl = template_from_str(
        "{% from 'macros/common_macros.lua.j2' import modules_unload %}{{ modules_unload(module_name) }}"
    )
    assert tmpl.render(module_name=val) == f"modules.unload('{val}')"


@pytest.mark.parametrize("val,name", [(True, "module_name_to_load"), (False, "module_name_to_unload")])
def test_module_loader(val, name):
    tmpl = template_from_str(
        "{% from 'macros/common_macros.lua.j2' import module_loader %}{{ module_loader(bool, module_name) }}"
    )
    lua = tmpl.render(bool=val, module_name=name)
    if val is True:
        assert lua == f"modules.load('{name}')"
    elif val is False:
        assert lua == f"modules.load('{name}')\nmodules.unload('{name}')"


# TABLES


@pytest.mark.parametrize(
    "val,lua",
    [
        ("string", "'string'"),
        (["s1", "s2", "s3"], "{'s1','s2','s3',}"),
    ],
)
def test_table_or_string(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/common_macros.lua.j2' import table_or_string %}{{ table_or_string(val) }}"
    )
    assert tmpl.render(val=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        ("2001:DB8::d0c", "kres.str2ip('2001:DB8::d0c')"),
        (["2001:DB8::d0c", "192.0.2.1"], "{kres.str2ip('2001:DB8::d0c'),kres.str2ip('192.0.2.1'),}"),
    ],
)
def test_table_or_str2ip(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/common_macros.lua.j2' import table_or_str2ip %}{{ table_or_str2ip(val) }}"
    )
    assert tmpl.render(val=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        ("AAAA", "kres.type.AAAA"),
        (["AAAA", "TXT"], "{kres.type.AAAA,kres.type.TXT,}"),
    ],
)
def test_table_or_qtype(val, lua):
    tmpl = template_from_str("{% from 'macros/common_macros.lua.j2' import table_or_qtype %}{{ table_or_qtype(val) }}")
    assert tmpl.render(val=val) == lua
