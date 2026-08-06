from pytest import raises

from knot_resolver.datamodel.lua_schema import LuaSchema
from knot_resolver.utils.modeling.exceptions import DataValidationError


def test_invalid():
    with raises(DataValidationError):
        LuaSchema({"script": "-- lua script", "script-file": "path/to/file"})
