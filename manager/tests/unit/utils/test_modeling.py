from typing import Any, Dict, List, Optional, Tuple, Union

from pytest import raises
from typing_extensions import Literal

from knot_resolver_manager.exceptions import SchemaException
from knot_resolver_manager.utils import SchemaNode
from knot_resolver_manager.utils.parsing import parse_json, parse_yaml


def test_primitive():
    class TestSchema(SchemaNode):
        i: int
        s: str
        b: bool

    yaml = """
i: 5
s: test
b: false
"""

    o = TestSchema(parse_yaml(yaml))
    assert o.i == 5
    assert o.s == "test"
    assert o.b == False


def test_parsing_primitive_exceptions():
    class TestStr(SchemaNode):
        s: str

    # int and float are allowed inputs for string
    with raises(SchemaException):
        TestStr(parse_yaml("s: false"))  # bool

    class TestInt(SchemaNode):
        i: int

    with raises(SchemaException):
        TestInt(parse_yaml("i: false"))  # bool
    with raises(SchemaException):
        TestInt(parse_yaml('i: "5"'))  # str
    with raises(SchemaException):
        TestInt(parse_yaml("i: 5.5"))  # float

    class TestBool(SchemaNode):
        b: bool

    with raises(SchemaException):
        TestBool(parse_yaml("b: 5"))  # int
    with raises(SchemaException):
        TestBool(parse_yaml('b: "5"'))  # str
    with raises(SchemaException):
        TestBool(parse_yaml("b: 5.5"))  # float


def test_nested():
    class LowerSchema(SchemaNode):
        i: int

    class UpperSchema(SchemaNode):
        l: LowerSchema

    yaml = """
l:
  i: 5
"""

    o = UpperSchema(parse_yaml(yaml))
    assert o.l.i == 5


def test_simple_compount_types():
    class TestSchema(SchemaNode):
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


def test_nested_compound_types():
    class TestSchema(SchemaNode):
        o: Optional[Dict[str, str]]

    yaml = """
o:
  key: val
"""

    o = TestSchema(parse_yaml(yaml))
    assert o.o == {"key": "val"}


def test_dash_conversion():
    class TestSchema(SchemaNode):
        awesome_field: Dict[str, str]

    yaml = """
awesome-field:
  awesome-key: awesome-value
"""

    o = TestSchema(parse_yaml(yaml))
    assert o.awesome_field["awesome-key"] == "awesome-value"


def test_nested_compount_types2():
    class TestSchema(SchemaNode):
        i: int
        o: Optional[Dict[str, str]]

    yaml = "i: 5"

    o = TestSchema(parse_yaml(yaml))
    assert o.i == 5
    assert o.o is None


def test_partial_mutations():
    class InnerSchema(SchemaNode):
        size: int = 5

    class ConfPreviousSchema(SchemaNode):
        workers: Union[Literal["auto"], int] = 1
        lua_config: Optional[str] = None
        inner: InnerSchema = InnerSchema()

    class ConfSchema(SchemaNode):
        _PREVIOUS_SCHEMA = ConfPreviousSchema

        workers: int
        lua_config: Optional[str]
        inner: InnerSchema

        def _workers(self, obj: Any) -> Any:
            if "workers" in obj and obj["workers"] == "auto":
                return 8
            return obj["workers"]

        def _validate(self) -> None:
            if self.workers < 0:
                raise ValueError("Number of workers must be non-negative")

    yaml = """
    workers: auto
    lua-config: something
    """

    d = parse_yaml(yaml)
    o = ConfSchema(d)
    assert o.lua_config == "something"
    assert o.inner.size == 5
    assert o.workers == 8

    # replacement of 'lua-config' attribute
    upd = d.update("/lua-config", parse_json('"new_value"'))
    o = ConfSchema(upd)
    assert o.lua_config == "new_value"
    assert o.inner.size == 5
    assert o.workers == 8

    # replacement of the whole tree
    o = ConfSchema(d.update("/", parse_json('{"inner": {"size": 55}}')))
    assert o.lua_config is None
    assert o.workers == 1
    assert o.inner.size == 55

    # replacement of 'inner' subtree
    o = ConfSchema(d.update("/inner", parse_json('{"size": 33}')))
    assert o.lua_config == "something"
    assert o.workers == 8
    assert o.inner.size == 33

    # raise validation SchemaException
    with raises(SchemaException):
        o = ConfSchema(d.update("/", parse_json('{"workers": -5}')))


def test_eq():
    class A(SchemaNode):
        field: int

    class B(SchemaNode):
        a: A
        field: str

    b1 = B({"a": {"field": 6}, "field": "val"})
    b2 = B({"a": {"field": 6}, "field": "val"})
    b_diff = B({"a": {"field": 7}, "field": "val"})

    assert b1 == b2
    assert b2 != b_diff
    assert b1 != b_diff
    assert b_diff == b_diff
