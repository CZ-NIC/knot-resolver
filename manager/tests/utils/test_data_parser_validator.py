from typing import Dict, List, Optional, Tuple, Union

from pytest import raises
from typing_extensions import Literal

from knot_resolver_manager.exceptions import DataParsingException
from knot_resolver_manager.utils import DataParser, DataValidator, Format


def test_primitive():
    class TestClass(DataParser):
        i: int
        s: str
        b: bool

    class TestClassStrict(DataValidator):
        i: int
        s: str
        b: bool

        def _validate(self) -> None:
            pass

    yaml = """
i: 5
s: test
b: false
"""

    obj = TestClass.from_yaml(yaml)
    assert obj.i == 5
    assert obj.s == "test"
    assert obj.b == False

    strict = TestClassStrict(obj)
    assert strict.i == 5
    assert strict.s == "test"
    assert strict.b == False

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.i == b.i == obj.i
    assert a.s == b.s == obj.s
    assert a.b == b.b == obj.b


def test_parsing_primitive_exceptions():
    class TestStr(DataParser):
        s: str

    # int and float are allowed inputs for string
    with raises(DataParsingException):
        TestStr.from_yaml("s: false")  # bool

    class TestInt(DataParser):
        i: int

    with raises(DataParsingException):
        TestInt.from_yaml("i: false")  # bool
    with raises(DataParsingException):
        TestInt.from_yaml('i: "5"')  # str
    with raises(DataParsingException):
        TestInt.from_yaml("i: 5.5")  # float

    class TestBool(DataParser):
        b: bool

    with raises(DataParsingException):
        TestBool.from_yaml("b: 5")  # int
    with raises(DataParsingException):
        TestBool.from_yaml('b: "5"')  # str
    with raises(DataParsingException):
        TestBool.from_yaml("b: 5.5")  # float


def test_nested():
    class Lower(DataParser):
        i: int

    class Upper(DataParser):
        l: Lower

    class LowerStrict(DataValidator):
        i: int

        def _validate(self) -> None:
            pass

    class UpperStrict(DataValidator):
        l: LowerStrict

        def _validate(self) -> None:
            pass

    yaml = """
l:
  i: 5
"""

    obj = Upper.from_yaml(yaml)
    assert obj.l.i == 5

    strict = UpperStrict(obj)
    assert strict.l.i == 5

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = Upper.from_yaml(y)
    b = Upper.from_json(j)
    assert a.l.i == b.l.i == obj.l.i


def test_simple_compount_types():
    class TestClass(DataParser):
        l: List[int]
        d: Dict[str, str]
        t: Tuple[str, int]
        o: Optional[int]

    class TestClassStrict(DataValidator):
        l: List[int]
        d: Dict[str, str]
        t: Tuple[str, int]
        o: Optional[int]

        def _validate(self) -> None:
            pass

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

    obj = TestClass.from_yaml(yaml)
    assert obj.l == [1, 2, 3, 4, 5]
    assert obj.d == {"something": "else", "w": "all"}
    assert obj.t == ("test", 5)
    assert obj.o is None

    strict = TestClassStrict(obj)
    assert strict.l == [1, 2, 3, 4, 5]
    assert strict.d == {"something": "else", "w": "all"}
    assert strict.t == ("test", 5)
    assert strict.o is None

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.l == b.l == obj.l
    assert a.d == b.d == obj.d
    assert a.t == b.t == obj.t
    assert a.o == b.o == obj.o


def test_nested_compound_types():
    class TestClass(DataParser):
        o: Optional[Dict[str, str]]

    class TestClassStrict(DataValidator):
        o: Optional[Dict[str, str]]

        def _validate(self) -> None:
            pass

    yaml = """
o:
  key: val
"""

    obj = TestClass.from_yaml(yaml)
    assert obj.o == {"key": "val"}

    strict = TestClassStrict(obj)
    assert strict.o == {"key": "val"}

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.o == b.o == obj.o


def test_nested_compount_types2():
    class TestClass(DataParser):
        i: int
        o: Optional[Dict[str, str]]

    class TestClassStrict(DataValidator):
        i: int
        o: Optional[Dict[str, str]]

        def _validate(self) -> None:
            pass

    yaml = "i: 5"

    obj = TestClass.from_yaml(yaml)
    assert obj.i == 5
    assert obj.o is None

    strict = TestClassStrict(obj)
    assert strict.i == 5
    assert strict.o is None

    y = obj.dump_to_yaml()
    j = obj.dump_to_json()
    a = TestClass.from_yaml(y)
    b = TestClass.from_json(j)
    assert a.i == b.i == obj.i
    assert a.o == b.o == obj.o


def test_partial_mutations():
    class Inner(DataParser):
        size: int = 5

    class ConfData(DataParser):
        workers: Union[Literal["auto"], int] = 1
        lua_config: Optional[str] = None
        inner: Inner = Inner()

    class InnerStrict(DataValidator):
        size: int

        def _validate(self) -> None:
            pass

    class ConfDataStrict(DataValidator):
        workers: int
        lua_config: Optional[str]
        inner: InnerStrict

        def _workers(self, data: ConfData) -> int:
            if data.workers == "auto":
                return 8
            else:
                return data.workers

        def _validate(self) -> None:
            if self.workers < 0:
                raise ValueError("Number of workers must be non-negative")

    yaml = """
    workers: auto
    lua-config: something
    """

    conf = ConfData.from_yaml(yaml)

    x = ConfDataStrict(conf)
    assert x.lua_config == "something"
    assert x.inner.size == 5
    assert x.workers == 8

    y = conf.dump_to_yaml()
    j = conf.dump_to_json()
    a = ConfData.from_yaml(y)
    b = ConfData.from_json(j)
    assert a.workers == b.workers == conf.workers
    assert a.lua_config == b.lua_config == conf.lua_config
    assert a.inner.size == b.inner.size == conf.inner.size

    # replacement of 'lua-config' attribute
    x = ConfDataStrict(conf.copy_with_changed_subtree(Format.JSON, "/lua-config", '"new_value"'))
    assert x.lua_config == "new_value"
    assert x.inner.size == 5
    assert x.workers == 8

    # replacement of the whole tree
    x = ConfDataStrict(conf.copy_with_changed_subtree(Format.JSON, "/", '{"inner": {"size": 55}}'))
    assert x.lua_config is None
    assert x.workers == 1
    assert x.inner.size == 55

    # replacement of 'inner' subtree
    x = ConfDataStrict(conf.copy_with_changed_subtree(Format.JSON, "/inner", '{"size": 33}'))
    assert x.lua_config == "something"
    assert x.workers == 8
    assert x.inner.size == 33
