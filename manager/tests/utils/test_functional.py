from knot_resolver_manager.utils.functional import all_matches, contains_element_matching, foldl


def test_foldl():
    lst = list(range(10))

    assert foldl(lambda x, y: x + y, 0, lst) == sum(range(10))
    assert foldl(lambda x, y: x + y, 55, lst) == sum(range(10)) + 55


def test_containsElementMatching():
    lst = list(range(10))

    assert contains_element_matching(lambda e: e == 5, lst)
    assert not contains_element_matching(lambda e: e == 11, lst)


def test_matches_all():
    lst = list(range(10))

    assert all_matches(lambda x: x >= 0, lst)
    assert not all_matches(lambda x: x % 2 == 0, lst)
