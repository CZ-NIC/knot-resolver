from pytest import raises

from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.exceptions import KresManagerException


def test_invalid():
    with raises(KresManagerException):
        LuaSchema({"script": "-- lua script", "script-file": "path/to/file"})
