from typing import Text
from jinja2 import Environment

from .datamodel import ConfData

_LUA_TEMPLATE_STR = """
{% if lua_config -%}
{{ config.lua_config }}
{% endif -%}
"""

_ENV = Environment(enable_async=True)
_LUA_TEMPLATE = _ENV.from_string(_LUA_TEMPLATE_STR)


async def render_lua(config: ConfData) -> Text:
    return await _LUA_TEMPLATE.render_async(config=config)


async def parse_yaml(yaml: str) -> ConfData:
    config = ConfData.from_yaml(yaml)
    await config.validate()
    return config
