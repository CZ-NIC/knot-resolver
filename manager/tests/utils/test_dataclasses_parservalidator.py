from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from knot_resolver_manager.utils.dataclasses_parservalidator import DataclassParserValidatorMixin, Format


def test_parsing_primitive():
    @dataclass
    class TestClass(DataclassParserValidatorMixin):
        i: int
        s: str

        def _validate(self):
            pass

    yaml = """i: 5
s: "test"
"""

    obj = TestClass.from_yaml(yaml)

    assert obj.i == 5
    assert obj.s == "test"


def test_parsing_nested():
    @dataclass
    class Lower(DataclassParserValidatorMixin):
        i: int

        def _validate(self):
            pass

    @dataclass
    class Upper(DataclassParserValidatorMixin):
        l: Lower

        def _validate(self):
            pass

    yaml = """l:
  i: 5"""

    obj = Upper.from_yaml(yaml)
    assert obj.l.i == 5


def test_simple_compount_types():
    @dataclass
    class TestClass(DataclassParserValidatorMixin):
        l: List[int]
        d: Dict[str, str]
        t: Tuple[str, int]
        o: Optional[int]

        def _validate(self):
            pass

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
    class TestClass(DataclassParserValidatorMixin):
        o: Optional[Dict[str, str]]

        def _validate(self):
            pass

    yaml = """o:
  key: val"""

    obj = TestClass.from_yaml(yaml)

    assert obj.o == {"key": "val"}


def test_nested_compount_types2():
    @dataclass
    class TestClass(DataclassParserValidatorMixin):
        i: int
        o: Optional[Dict[str, str]]

        def _validate(self):
            pass

    yaml = "i: 5"

    obj = TestClass.from_yaml(yaml)

    assert obj.o is None


def test_real_failing_dummy_confdata():
    @dataclass
    class ConfData(DataclassParserValidatorMixin):
        num_workers: int = 1
        lua_config: Optional[str] = None

        def _validate(self):
            if self.num_workers < 0:
                raise Exception("Number of workers must be non-negative")

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


def test_partial_mutations():
    @dataclass
    class Inner(DataclassParserValidatorMixin):
        number: int

        def _validate(self):
            pass

    @dataclass
    class ConfData(DataclassParserValidatorMixin):
        num_workers: int = 1
        lua_config: Optional[str] = None
        inner: Inner = Inner(5)

        def _validate(self):
            if self.num_workers < 0:
                raise Exception("Number of workers must be non-negative")

    data = ConfData(5, "something", Inner(10))

    x = data.copy_with_changed_subtree(Format.JSON, "/lua_config", '"new_value"')
    assert x.lua_config == "new_value"
    assert x.num_workers == 5
    assert x.inner.number == 10

    x = data.copy_with_changed_subtree(Format.JSON, "/inner", '{"number": 55}')
    assert x.lua_config == "something"
    assert x.num_workers == 5
    assert x.inner.number == 55

    x = data.copy_with_changed_subtree(Format.JSON, "/", '{"inner": {"number": 55}}')
    assert x.lua_config is None
    assert x.num_workers == 1
    assert x.inner.number == 55
