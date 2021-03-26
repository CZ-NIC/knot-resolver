from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import pytest
import strictyaml
from strictyaml import EmptyDict, FixedSeq, Float, Int, Map, MapPattern, Seq, Str

from knot_resolver_manager.utils import dataclass_strictyaml_schema
from knot_resolver_manager.utils.dataclasses_yaml import dataclass_strictyaml


def _schema_eq(schema1, schema2) -> bool:
    """
    Hacky way to determine, whether two schemas are the same... It works well, so why not... :)
    """
    return str(schema1) == str(schema2)


def test_empty_class():
    @dataclass_strictyaml_schema
    class TestClass:
        pass

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, EmptyDict())


def test_int_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: int

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Int()}))


def test_string_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: str

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Str()}))


def test_float_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: float

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Float()}))


def test_multiple_fields():
    @dataclass_strictyaml_schema
    class TestClass:
        field1: str
        field2: int
        field3: float

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA,
        Map({"field1": Str(), "field2": Int(), "field3": Float()}),
    )


def test_list_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: List[str]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Seq(Str())}))


def test_dict_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Dict[str, int]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Str(), Int())}))


def test_optional_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Optional[int]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({strictyaml.Optional("field"): Int()}))


def test_nested_dict_list():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Dict[str, List[int]]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Str(), Seq(Int()))}))


@pytest.mark.xfail(strict=True)
def test_nested_dict_key_list():
    """
    List can't be a dict key, so this should fail
    """

    @dataclass_strictyaml_schema
    class TestClass:
        field: Dict[List[int], List[int]]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Seq(Int()), Seq(Int()))}))


def test_nested_list():
    @dataclass_strictyaml_schema
    class TestClass:
        field: List[List[List[List[int]]]]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Seq(Seq(Seq(Seq(Int()))))}))


def test_tuple_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Tuple[str, int]

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": FixedSeq([Str(), Int()])}))


def test_nested_tuple():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Tuple[str, Dict[str, int], List[List[int]]]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA,
        Map({"field": FixedSeq([Str(), MapPattern(Str(), Int()), Seq(Seq(Int()))])}),
    )


def test_chained_classes():
    @dataclass_strictyaml_schema
    class TestClass:
        field: int

    @dataclass_strictyaml_schema
    class CompoundClass:
        c: TestClass

    assert _schema_eq(CompoundClass.STRICTYAML_SCHEMA, Map({"c": Map({"field": Int()})}))


def test_combined_with_dataclass():
    from dataclasses import dataclass

    @dataclass
    @dataclass_strictyaml_schema
    class TestClass:
        field: int

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Int()}))


def test_combined_with_dataclass2():
    from dataclasses import dataclass

    @dataclass_strictyaml_schema
    @dataclass
    class TestClass:
        field: int

    assert _schema_eq(TestClass.STRICTYAML_SCHEMA, Map({"field": Int()}))


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
    @dataclass_strictyaml
    class Lower:
        i: int

    @dataclass
    @dataclass_strictyaml
    class Upper:
        l: Lower

    yaml = """l:
  i: 5"""

    obj = Upper.from_yaml(yaml)
    assert obj.l.i == 5


def test_simple_compount_types():
    @dataclass
    @dataclass_strictyaml
    class TestClass:
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
    @dataclass_strictyaml
    class TestClass:
        o: Optional[Dict[str, str]]

    yaml = """o:
  key: val"""

    obj = TestClass.from_yaml(yaml)

    assert obj.o == {"key": "val"}


def test_nested_compount_types2():
    @dataclass
    @dataclass_strictyaml
    class TestClass:
        i: int
        o: Optional[Dict[str, str]]

    yaml = "i: 5"

    obj = TestClass.from_yaml(yaml)

    assert obj.o is None
