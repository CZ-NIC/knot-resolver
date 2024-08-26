from typing import Any, Dict, List, Optional, Tuple, Type, Union

import pytest
from pytest import raises
from typing_extensions import Literal

from knot_resolver.utils.modeling import ConfigSchema, parse_json, parse_yaml
from knot_resolver.utils.modeling.exceptions import DataDescriptionError, DataValidationError


class _TestBool(ConfigSchema):
    v: bool


class _TestInt(ConfigSchema):
    v: int


class _TestStr(ConfigSchema):
    v: str


@pytest.mark.parametrize("val,exp", [("false", False), ("true", True), ("False", False), ("True", True)])
def test_parsing_bool_valid(val: str, exp: bool):
    assert _TestBool(parse_yaml(f"v: {val}")).v == exp


@pytest.mark.parametrize("val", ["0", "1", "5", "'true'", "'false'", "5.5"])  # int, str, float
def test_parsing_bool_invalid(val: str):
    with raises(DataValidationError):
        _TestBool(parse_yaml(f"v: {val}"))


@pytest.mark.parametrize("val,exp", [("0", 0), ("5353", 5353), ("-5001", -5001)])
def test_parsing_int_valid(val: str, exp: int):
    assert _TestInt(parse_yaml(f"v: {val}")).v == exp


@pytest.mark.parametrize("val", ["false", "'5'", "5.5"])  # bool, str, float
def test_parsing_int_invalid(val: str):
    with raises(DataValidationError):
        _TestInt(parse_yaml(f"v: {val}"))


# int and float are allowed inputs for string
@pytest.mark.parametrize("val,exp", [("test", "test"), (65, "65"), (5.5, "5.5")])
def test_parsing_str_valid(val: Any, exp: str):
    assert _TestStr(parse_yaml(f"v: {val}")).v == exp


def test_parsing_str_invalid():
    with raises(DataValidationError):
        _TestStr(parse_yaml("v: false"))  # bool


def test_parsing_list_empty():
    class ListSchema(ConfigSchema):
        empty: List[Any]

    with raises(DataValidationError):
        ListSchema(parse_yaml("empty: []"))


@pytest.mark.parametrize("typ,val", [(_TestInt, 5), (_TestBool, False), (_TestStr, "test")])
def test_parsing_nested(typ: Type[ConfigSchema], val: Any):
    class UpperSchema(ConfigSchema):
        l: typ

    yaml = f"""
l:
  v: {val}
"""

    o = UpperSchema(parse_yaml(yaml))
    assert o.l.v == val


def test_parsing_simple_compound_types():
    class TestSchema(ConfigSchema):
        l: List[int]
        d: Dict[str, str]
        t: Tuple[str, int]
        o: Optional[int]

    yaml = """
l:
  - 1
  - 2
  - 3
  - 4
  - 5
d:
  something: else
  w: all
t:
  - test
  - 5
"""

    o = TestSchema(parse_yaml(yaml))
    assert o.l == [1, 2, 3, 4, 5]
    assert o.d == {"something": "else", "w": "all"}
    assert o.t == ("test", 5)
    assert o.o is None


def test_parsing_nested_compound_types():
    class TestSchema(ConfigSchema):
        i: int
        o: Optional[Dict[str, str]]

    yaml1 = "i: 5"
    yaml2 = f"""
{yaml1}
o:
  key1: str1
  key2: str2
    """

    o = TestSchema(parse_yaml(yaml1))
    assert o.i == 5
    assert o.o is None

    o = TestSchema(parse_yaml(yaml2))
    assert o.i == 5
    assert o.o == {"key1": "str1", "key2": "str2"}


def test_dash_conversion():
    class TestSchema(ConfigSchema):
        awesome_field: Dict[str, str]

    yaml = """
awesome-field:
  awesome-key: awesome-value
"""

    o = TestSchema(parse_yaml(yaml))
    assert o.awesome_field["awesome-key"] == "awesome-value"


def test_eq():
    class B(ConfigSchema):
        a: _TestInt
        field: str

    b1 = B({"a": {"v": 6}, "field": "val"})
    b2 = B({"a": {"v": 6}, "field": "val"})
    b_diff = B({"a": {"v": 7}, "field": "val"})

    assert b1 == b2
    assert b2 != b_diff
    assert b1 != b_diff
    assert b_diff == b_diff


def test_docstring_parsing_valid():
    class NormalDescription(ConfigSchema):
        """
        Does nothing special
        Really
        """

    desc = NormalDescription.json_schema()
    assert desc["description"] == "Does nothing special\nReally"

    class FieldsDescription(ConfigSchema):
        """
        This is an awesome test class
        ---
        field: This field does nothing interesting
        value: Neither does this
        """

        field: str
        value: int

    schema = FieldsDescription.json_schema()
    assert schema["description"] == "This is an awesome test class"
    assert schema["properties"]["field"]["description"] == "This field does nothing interesting"
    assert schema["properties"]["value"]["description"] == "Neither does this"

    class NoDescription(ConfigSchema):
        nothing: str

    _ = NoDescription.json_schema()


def test_docstring_parsing_invalid():
    class AdditionalItem(ConfigSchema):
        """
        This class is wrong
        ---
        field: nope
        nothing: really nothing
        """

        nothing: str

    with raises(DataDescriptionError):
        _ = AdditionalItem.json_schema()

    class WrongDescription(ConfigSchema):
        """
        This class is wrong
        ---
        other: description
        """

        nothing: str

    with raises(DataDescriptionError):
        _ = WrongDescription.json_schema()
