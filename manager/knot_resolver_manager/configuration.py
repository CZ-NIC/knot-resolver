from typing import Text

from jinja2 import Environment, Template

from .datamodel import KresConfig

_LUA_TEMPLATE_STR = """
modules = {
{%- if cfg.dns64 %}
    dns64 = '{{ cfg.dns64.prefix }}' }   -- dns64
{%- endif %}
}

-- lua
{%- if cfg.lua.script %}
{{ cfg.lua.script }}
{%- endif %}
"""

_ENV = Environment(enable_async=True)
_LUA_TEMPLATE: Template = _ENV.from_string(_LUA_TEMPLATE_STR)


async def render_lua(config: KresConfig) -> Text:
    return await _LUA_TEMPLATE.render_async(cfg=config)


async def load_file(path: str) -> KresConfig:
    try:
        with open(path, "r") as file:
            yaml_str = file.read()
    except FileNotFoundError:
        # return defaults
        return KresConfig()
    return KresConfig.from_yaml(yaml_str)
