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