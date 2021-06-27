from knot_resolver_manager.utils import containsElementMatching, foldl


def test_foldl():
    lst = list(range(10))

    assert foldl(lambda x, y: x + y, 0, lst) == sum(range(10))
    assert foldl(lambda x, y: x + y, 55, lst) == sum(range(10)) + 55


def test_containsElementMatching():
    lst = list(range(10))

    assert containsElementMatching(lambda e: e == 5, lst)
    assert not containsElementMatching(lambda e: e == 11, lst)
