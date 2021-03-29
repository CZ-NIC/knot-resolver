import json
from typing import Text

import yaml
from jinja2 import Environment, Template

from .datamodel import KresConfig

_LUA_TEMPLATE_STR = """
{% if lua_config -%}
{{ cfg.lua.script }}
{% endif -%}
"""

_ENV = Environment(enable_async=True)
_LUA_TEMPLATE: Template = _ENV.from_string(_LUA_TEMPLATE_STR)


async def render_lua(config: KresConfig) -> Text:
    return await _LUA_TEMPLATE.render_async(cfg=config)


async def parse_yaml(yaml_str: str) -> KresConfig:
    data = yaml.safe_load(yaml_str)
    config = KresConfig(**data)
    await config.validate()
    return config


async def parse_json(json_str: str) -> KresConfig:
    data = json.loads(json_str)
    config: KresConfig = KresConfig(**data)
    await config.validate()
    return config


async def load_file(path: str) -> KresConfig:
    try:
        with open(path, "r") as file:
            yaml_str = file.read()
    except FileNotFoundError:
        # return defaults
        return KresConfig()
    return parse_yaml(yaml_str)
