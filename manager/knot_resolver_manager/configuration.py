from typing import Text

from jinja2 import Environment, Template

from .datamodel import KresConfig

_LUA_TEMPLATE_STR = """
{% if cfg.server.hostname %}
-- server.hostname
hostname('{{ cfg.server.hostname }}')
{% endif %}

-- network.interfaces
{% for item in cfg.network.interfaces %}
net.listen('{{ item.get_address() }}', {{ item.get_port() if item.get_port() else 'nil' }}, {
    kind = '{{ item.kind if item.kind != 'dot' else 'tls' }}',
    freebind = {{ 'true' if item.freebind else 'false'}}
})
{% endfor %}

-- network.edns-buffer-size
net.bufsize({{ cfg.network.edns_buffer_size.get_downstream() }}, {{ cfg.network.edns_buffer_size.get_upstream() }})

-- modules
modules = {
    'hints > iterate',   -- Load /etc/hosts and allow custom root hints",
    'stats',             -- Track internal statistics",
{% if cfg.options.prediction %}
    predict = {          -- Prefetch expiring/frequent records"
        window = {{ cfg.options.prediction.get_window() }},
        period = {{ cfg.options.prediction.period }}
    },
{% endif %}
{% if cfg.dns64 %}
    dns64 = '{{ cfg.dns64.prefix }}', -- dns64
{% endif %}
}

-- cache
cache.open({{ cfg.cache.get_size_max() }}, 'lmdb://{{ cfg.cache.storage }}')

-- logging level
verbose({{ 'true' if cfg.logging.level > 3 else 'false'}})

{% if cfg.lua.script %}
-- lua
{{ cfg.lua.script }}
{% endif %}
"""

_ENV = Environment(enable_async=True, trim_blocks=True, lstrip_blocks=True)
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
