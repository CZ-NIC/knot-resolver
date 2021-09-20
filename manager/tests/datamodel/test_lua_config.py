from pytest import raises

from knot_resolver_manager.datamodel.lua_config import Lua
from knot_resolver_manager.exceptions import KresdManagerException

tree = {"script-only": True, "script": "-- lua script"}
strict = Lua(tree)


def test_validating():
    assert strict.script_only == True
    assert strict.script == "-- lua script"


def test_exception_raises():
    with raises(KresdManagerException):
        Lua({"script": "-- lua script", "script-file": "path/to/file"})
