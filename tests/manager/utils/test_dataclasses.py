from knot_resolver_manager.compat.dataclasses import dataclass, is_dataclass


def test_dataclass():
    @dataclass
    class A:
        b: int = 5

    val = A(6)
    assert val.b == 6

    val = A(b=7)
    assert val.b == 7

    assert is_dataclass(A)
