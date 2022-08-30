from pyparsing import empty

from knot_resolver_manager.utils.modeling import ParsedTree


def test_etag():
    empty1 = ParsedTree({})
    empty2 = ParsedTree({})

    assert empty1.etag == empty2.etag

    something1 = ParsedTree({"something": 1})
    something2 = ParsedTree({"something": 2})
    assert empty1.etag != something1.etag
    assert something1.etag != something2.etag
