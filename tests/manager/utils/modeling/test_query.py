from pytest import raises

from knot_resolver_manager.utils.modeling.query import query


def test_example_from_spec():
    # source of the example: https://jsonpatch.com/
    original = {"baz": "qux", "foo": "bar"}
    patch = [
        {"op": "replace", "path": "/baz", "value": "boo"},
        {"op": "add", "path": "/hello", "value": ["world"]},
        {"op": "remove", "path": "/foo"},
    ]
    expected = {"baz": "boo", "hello": ["world"]}

    result, _ = query(original, "patch", "", patch)

    assert result == expected
