from knot_resolver_manager.utils.dataclasses_yaml import (
    StrictyamlParser,
    dataclass_strictyaml,
)
from knot_resolver_manager.utils import dataclass_strictyaml_schema
from typing import List, Dict, Optional, Tuple
from strictyaml import Map, Str, EmptyDict, Int, Float, Seq, MapPattern, FixedSeq
import strictyaml
import pytest
from dataclasses import dataclass


def test_parsing_primitive():
    @dataclass
    @dataclass_strictyaml
    class TestClass:
        i: int
        s: str
        f: float

    yaml = """i: 5
s: "test"
f: 3.14"""

    obj = TestClass.from_yaml(yaml)

    assert obj.i == 5
    assert obj.s == "test"
    assert obj.f == 3.14


def test_parsing_nested():
    @dataclass
    @dataclass_strictyaml_schema
    class Lower:
        i: int

    @dataclass
    class Upper(StrictyamlParser):
        l: Lower

    yaml = """l:
  i: 5"""

    obj = Upper.from_yaml(yaml)
    assert obj.l.i == 5


def test_simple_compount_types():
    @dataclass
    class TestClass(StrictyamlParser):
        l: List[int]
        d: Dict[str, str]
        t: Tuple[str, int]
        o: Optional[int]

    yaml = """l:
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
  - 5"""

    obj = TestClass.from_yaml(yaml)

    assert obj.l == [1, 2, 3, 4, 5]
    assert obj.d == {"something": "else", "w": "all"}
    assert obj.t == ("test", 5)
    assert obj.o is None


def test_nested_compount_types():
    @dataclass
    class TestClass(StrictyamlParser):
        o: Optional[Dict[str, str]]

    yaml = """o:
  key: val"""

    obj = TestClass.from_yaml(yaml)

    assert obj.o == {"key": "val"}


def test_nested_compount_types2():
    @dataclass
    class TestClass(StrictyamlParser):
        i: int
        o: Optional[Dict[str, str]]

    yaml = "i: 5"

    obj = TestClass.from_yaml(yaml)

    assert obj.o is None
