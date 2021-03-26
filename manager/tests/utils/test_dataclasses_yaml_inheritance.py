from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import pytest
import strictyaml
from strictyaml import EmptyDict, FixedSeq, Float, Int, Map, MapPattern, Seq, Str

from knot_resolver_manager.utils import dataclass_strictyaml_schema
from knot_resolver_manager.utils.dataclasses_yaml import StrictyamlParser, dataclass_strictyaml


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


def test_real_failing_dummy_confdata():
    @dataclass
    class ConfData(StrictyamlParser):
        num_workers: int = 1
        lua_config: Optional[str] = None

        async def validate(self) -> bool:
            if self.num_workers < 0:
                raise Exception("Number of workers must be non-negative")

            return True

    # prepare the payload
    lua_config = "dummy"
    config = f"""
num_workers: 4
lua_config: |
  { lua_config }"""

    data = ConfData.from_yaml(config)

    assert type(data.num_workers) == int
    assert data.num_workers == 4
    assert type(data.lua_config) == str
    assert data.lua_config == "dummy"
