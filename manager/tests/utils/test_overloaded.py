from typing import Optional
from knot_resolver_manager.utils.overload import overloaded


def test_simple():
    func: overloaded[None] = overloaded()

    @func.add(int)
    def f1(a: int) -> None:
        assert type(a) == int
    
    @func.add(str)
    def f2(a: str) -> None:
        assert type(a) == str
    
    func("test")
    func(5)
    f1("test")
    f2(5)
    f1("test")
    f2(5)


def test_optional():
    func: overloaded[int] = overloaded()

    @func.add(Optional[int], str)
    def f1(a: Optional[int], b: str) -> int:
        assert a is None or type(a) == int
        assert type(b) == str
        return -1
    
    @func.add(Optional[str], int)
    def f2(a: Optional[str], b: int) -> int:
        assert a is None or type(a) == str
        assert type(b) == int
        return 1
    

    func(None, 5)
    func("str", 5)
    func(None, "str")
    func(5, "str")