from pytest import raises

from knot_resolver_manager.datamodel.lua_config import Lua, LuaStrict
from knot_resolver_manager.exceptions import KresdManagerException

yaml = """
script-only: true
script: |
    -- lua script"""

config = Lua.from_yaml(yaml)
strict = LuaStrict(config)


def test_parsing():
    assert config.script_only == True
    assert config.script == "-- lua script"


def test_validating():
    assert strict.script_only == True
    assert strict.script == "-- lua script"


def test_exception_raises():
    yaml2 = """
script: -- lua script
script-file: path/to/file
"""

    with raises(KresdManagerException):
        LuaStrict(Lua.from_yaml(yaml2))
