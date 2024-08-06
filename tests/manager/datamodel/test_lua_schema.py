from pytest import raises

from knot_resolver_manager.manager.datamodel.lua_schema import LuaSchema
from knot_resolver_manager.utils.modeling.exceptions import DataValidationError


def test_invalid():
    with raises(DataValidationError):
        LuaSchema({"script": "-- lua script", "script-file": "path/to/file"})
