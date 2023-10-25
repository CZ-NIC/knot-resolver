import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.network_schema import ListenSchema


@pytest.mark.parametrize(
    "val,lua",
    [
        ("2001:DB8::d0c", "'2001:DB8::d0c'"),
        (["2001:DB8::d0c", "192.0.2.1"], "{'2001:DB8::d0c','192.0.2.1',}"),
    ],
)
def test_table_or_server(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/network_macros.lua.j2' import table_or_server %}" "{{ table_or_server(val) }}"
    )
    assert tmpl.render(val=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            ListenSchema({"unix-socket": "/tmp/kresd-socket", "kind": "dot"}),
            """net.listen('/tmp/kresd-socket', nil, {
    kind = 'tls',
    freebind = false,
})
""",
        ),
        (
            ListenSchema({"unix-socket": ["/tmp/kresd-socket", "/tmp/kresd-socket2"], "kind": "dot"}),
            """net.listen('/tmp/kresd-socket', nil, {
    kind = 'tls',
    freebind = false,
})
net.listen('/tmp/kresd-socket2', nil, {
    kind = 'tls',
    freebind = false,
})
""",
        ),
        (
            ListenSchema({"interface": "::1@55", "freebind": True}),
            """net.listen('::1', 55, {
    kind = 'dns',
    freebind = true,
})
""",
        ),
        (
            ListenSchema({"interface": ["::1@55", "127.0.0.1@5353"]}),
            """net.listen('::1', 55, {
    kind = 'dns',
    freebind = false,
})
net.listen('127.0.0.1', 5353, {
    kind = 'dns',
    freebind = false,
})
""",
        ),
        (
            ListenSchema({"interface": "eth0", "kind": "doh2"}),
            """net.listen(net.eth0, 443, {
    kind = 'doh2',
    freebind = false,
})
""",
        ),
        (
            ListenSchema({"interface": ["eth0", "lo"], "port": 5555, "kind": "doh2"}),
            """net.listen(net.eth0, 5555, {
    kind = 'doh2',
    freebind = false,
})
net.listen(net.lo, 5555, {
    kind = 'doh2',
    freebind = false,
})
""",
        ),
    ],
)
def test_network_listen(val, lua):
    tmpl_str = """{% from 'macros/network_macros.lua.j2' import network_listen %}
{{ network_listen(listen) }}"""

    tmpl = template_from_str(tmpl_str)
    assert tmpl.render(listen=val) == lua
