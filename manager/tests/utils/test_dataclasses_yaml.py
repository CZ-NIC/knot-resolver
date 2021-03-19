from knot_resolver_manager.utils import dataclass_strictyaml_schema
from typing import List, Dict, Optional, Tuple
from strictyaml import Map, Str, EmptyDict, Int, Float, Seq, MapPattern, FixedSeq
import strictyaml
import pytest


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

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Str(), Int())})
    )


def test_optional_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Optional[int]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": strictyaml.Optional(Int())})
    )


def test_nested_dict_list():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Dict[str, List[int]]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Str(), Seq(Int()))})
    )


@pytest.mark.xfail(strict=True)
def test_nested_dict_key_list():
    """
    List can't be a dict key, so this should fail
    """

    @dataclass_strictyaml_schema
    class TestClass:
        field: Dict[List[int], List[int]]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": MapPattern(Seq(Int()), Seq(Int()))})
    )


def test_nested_list():
    @dataclass_strictyaml_schema
    class TestClass:
        field: List[List[List[List[int]]]]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": Seq(Seq(Seq(Seq(Int()))))})
    )


def test_tuple_field():
    @dataclass_strictyaml_schema
    class TestClass:
        field: Tuple[str, int]

    assert _schema_eq(
        TestClass.STRICTYAML_SCHEMA, Map({"field": FixedSeq([Str(), Int()])})
    )


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

    assert _schema_eq(
        CompoundClass.STRICTYAML_SCHEMA, Map({"c": Map({"field": Int()})})
    )


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
