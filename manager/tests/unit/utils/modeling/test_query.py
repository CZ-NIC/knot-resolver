from typing import List, Optional

from pytest import raises

from knot_resolver_manager.utils.modeling.base_schema import BaseSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError
from knot_resolver_manager.utils.modeling.parsing import parse_json, parse_yaml


class InnerSchema(BaseSchema):
    size: int = 5
    lst: Optional[List[int]]


class ConfSchema(BaseSchema):
    workers: int
    lua_config: Optional[str]
    inner: InnerSchema = InnerSchema()

    def _validate(self) -> None:
        super()._validate()
        if self.workers < 0:
            raise DataValidationError("ee", "/workers")


YAML = """
workers: 1
lua-config: something
"""
REF = parse_yaml(YAML)


def test_patch():
    o = ConfSchema(REF)
    assert o.lua_config == "something"
    assert o.workers == 1
    assert o.inner.size == 5

    # replacement of 'lua-config' attribute
    upd, _resp = REF.query("patch", "/lua-config", parse_json('"new_value"'))
    o = ConfSchema(upd)
    assert o.lua_config == "new_value"
    assert o.inner.size == 5
    assert o.workers == 1

    # replacement of the whole tree
    upd, _resp = REF.query("patch", "/", parse_json('{"inner": {"size": 55}, "workers": 8}'))
    o = ConfSchema(upd)
    assert o.lua_config is None
    assert o.workers == 8
    assert o.inner.size == 55

    # raise validation DataValidationError
    with raises(DataValidationError):
        upd, _resp = REF.query("patch", "/", parse_json('{"workers": -5}'))
        o = ConfSchema(upd)


def test_put_and_delete():
    # insert 'inner' subtree
    upd, _resp = REF.query("put", "/inner", parse_json('{"size": 33}'))
    o = ConfSchema(upd)
    assert o.lua_config == "something"
    assert o.workers == 1
    assert o.inner.size == 33

    upd, _resp = upd.query("put", "/inner/lst", parse_json("[1,2,3]"))
    o = ConfSchema(upd)
    assert tuple(o.inner.lst or []) == tuple([1, 2, 3])

    upd, _resp = upd.query("delete", "/inner/lst/1")
    o = ConfSchema(upd)
    assert tuple(o.inner.lst or []) == tuple([1, 3])

    upd, _resp = upd.query("delete", "/inner/lst")
    o = ConfSchema(upd)
    assert o.inner.lst is None
