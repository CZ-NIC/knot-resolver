from pytest import raises

from knot_resolver_manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.exceptions import KresdManagerException

tree = {"script-only": True, "script": "-- lua script"}
strict = LuaSchema(tree)


def test_validating():
    assert strict.script_only == True
    assert strict.script == "-- lua script"


def test_exception_raises():
    with raises(KresdManagerException):
        LuaSchema({"script": "-- lua script", "script-file": "path/to/file"})
