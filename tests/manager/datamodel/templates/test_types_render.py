from typing import Any

import pytest
from jinja2 import Template

from knot_resolver.datamodel.types import EscapedStr
from knot_resolver.utils.modeling import ConfigSchema

str_template = Template("'{{ string }}'")


str_multiline_template = Template(
    """[[
{{ string.multiline() }}
]]"""
)


@pytest.mark.parametrize(
    "val,exp",
    [
        ("\a\b\f\n\r\t\v\\", "\a\b\f\n\r\t\v\\"),
        ("[[ test ]]", r"\[\[ test \]\]"),
        ("[ [ test ] ]", r"[ [ test ] ]"),
    ],
)
def test_escaped_str_multiline(val: Any, exp: str):
    class TestSchema(ConfigSchema):
        pattern: EscapedStr

    d = TestSchema({"pattern": val})
    assert (
        str_multiline_template.render(string=d.pattern)
        == f"""[[
{exp}
]]"""
    )


@pytest.mark.parametrize(
    "val,exp",
    [
        ("", ""),
        ("string", "string"),
        (2000, "2000"),
        ('"\a\b\f\n\r\t\v\\"', r"\"\a\b\f\n\r\t\v\\\""),
        ('""', r"\"\""),
        ("''", r"\'\'"),
        # fmt: off
        ('""', r"\"\""),
        ("''", r"\'\'"),
        # fmt: on
    ],
)
def test_escaped_str(val: Any, exp: str):
    class TestSchema(ConfigSchema):
        pattern: EscapedStr

    d = TestSchema({"pattern": val})
    assert str_template.render(string=d.pattern) == f"'{exp}'"
