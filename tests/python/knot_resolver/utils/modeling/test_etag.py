from pyparsing import empty

from knot_resolver.utils.etag import structural_etag


def test_etag():
    empty1 = {}
    empty2 = {}

    assert structural_etag(empty1) == structural_etag(empty2)

    something1 = {"something": 1}
    something2 = {"something": 2}
    assert structural_etag(empty1) != structural_etag(something1)
    assert structural_etag(something1) != structural_etag(something2)
