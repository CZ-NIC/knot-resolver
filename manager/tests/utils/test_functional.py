from knot_resolver_manager.utils import contains_element_matching, foldl


def test_foldl():
    lst = list(range(10))

    assert foldl(lambda x, y: x + y, 0, lst) == sum(range(10))
    assert foldl(lambda x, y: x + y, 55, lst) == sum(range(10)) + 55


def test_containsElementMatching():
    lst = list(range(10))

    assert contains_element_matching(lambda e: e == 5, lst)
    assert not contains_element_matching(lambda e: e == 11, lst)
