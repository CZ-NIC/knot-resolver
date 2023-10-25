import pytest

from knot_resolver_manager.datamodel.config_schema import template_from_str
from knot_resolver_manager.datamodel.forward_schema import ForwardOptionsSchema, ForwardSchema, ForwardServerSchema


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            ForwardOptionsSchema(),
            """{
    dnssec = true,
    auth = false
}""",
        ),
        (
            ForwardOptionsSchema({"dnssec": False, "authoritative": True}),
            """{
    dnssec = false,
    auth = true
}""",
        ),
    ],
)
def test_forward_options(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/forward_macros.lua.j2' import forward_options %}" "{{ forward_options(options) }}"
    )
    assert tmpl.render(options=val) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        (
            (
                "2001:148f:fffe::1",
                "tls",
                "odvr.nic.cz",
                "/path/to/ca-file.crt",
            ),
            """{
    '2001:148f:fffe::1',
    tls = true,
    hostname = 'odvr.nic.cz',
    ca_file = '/path/to/ca-file.crt',
}""",
        ),
        (
            (
                "2001:148f:fffe::1",
                None,
                None,
                None,
            ),
            """{
    '2001:148f:fffe::1',
    tls = false,
}""",
        ),
    ],
)
def test_forward_server_config(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/forward_macros.lua.j2' import forward_server_config %}"
        "{{ forward_server_config(address, transport, hostname, pin_sha256, ca_file) }}"
    )
    assert tmpl.render(address=val[0], transport=val[1], hostname=val[2], pin_sha256=None, ca_file=val[3]) == lua


@pytest.mark.parametrize(
    "val,lua",
    [
        ("185.43.135.1", "{ '185.43.135.1' },"),
        (
            ForwardServerSchema(
                {
                    "address": "2001:148f:fffe::1",
                    "transport": "tls",
                    "hostname": "odvr.nic.cz",
                    "ca-file": "/path/to/ca-file.crt",
                }
            ),
            """{
    '2001:148f:fffe::1',
    tls = true,
    hostname = 'odvr.nic.cz',
    ca_file = '/path/to/ca-file.crt',
},
""",
        ),
        (
            ForwardServerSchema(
                {
                    "address": ["2001:148f:fffe::1", "185.43.135.1"],
                    "transport": "tls",
                    "hostname": "odvr.nic.cz",
                    "ca-file": "/path/to/ca-file.crt",
                }
            ),
            """{
    '2001:148f:fffe::1',
    tls = true,
    hostname = 'odvr.nic.cz',
    ca_file = '/path/to/ca-file.crt',
},
{
    '185.43.135.1',
    tls = true,
    hostname = 'odvr.nic.cz',
    ca_file = '/path/to/ca-file.crt',
},
""",
        ),
    ],
)
def test_forward_server(val, lua):
    tmpl = template_from_str(
        "{% from 'macros/forward_macros.lua.j2' import forward_server %}" "{{ forward_server(server) }}"
    )
    assert tmpl.render(server=val) == lua


def test_policy_rule_forward_add():
    tmpl = template_from_str(
        "{% from 'macros/forward_macros.lua.j2' import policy_rule_forward_add %}"
        "{{ policy_rule_forward_add(subtree, options, servers) }}"
    )

    lua = """policy.rule_forward_add(
    'subtree',
    options,
    servers
)"""

    assert tmpl.render(subtree="subtree", options="options", servers="servers") == lua


# @pytest.mark.parametrize(
#     "val,lua",
#     [
#         (
#             ForwardSchema(
#                 {
#                     "subtree": ".",
#                     "servers": [
#                         {
#                             "address": ["2001:148f:fffe::1", "185.43.135.1"],
#                             "transport": "tls",
#                             "hostname": "odvr.nic.cz",
#                         }
#                     ],
#                     "options": {
#                         "authoritative": False,
#                         "dnssec": True,
#                     },
#                 }
#             ),
#             """policy.rule_forward_add(
#     '.',
#     {
#         dnssec = true,
#         auth = false,
#     },
#     {
#         {
#             '2001:148f:fffe::1',
#             tls = true,
#             hostname = 'odvr.nic.cz',
#         },
#         {
#             '185.43.135.1',
#             tls = true,
#             hostname = 'odvr.nic.cz',
#         },
#     },
# )""",
#         ),
#         (
#             ForwardSchema(
#                 {
#                     "subtree": ".",
#                     "servers": ["2001:148f:fffe::1", "185.43.135.1"],
#                     "options": {
#                         "authoritative": False,
#                         "dnssec": True,
#                     },
#                 }
#             ),
#             """policy.rule_forward_add(
#     '.',
#     {
#         dnssec = true,
#         auth = false,
#     },
#     {
#         '2001:148f:fffe::1',
#         '185.43.135.1',
#     },
# )""",
#         ),
#     ],
# )
# def test_policy_rule_forward_add(val, lua):
#     tmpl_str = """{% from 'macros/forward_macros.lua.j2' import forward %}
# {{ forward(fwd) }}"""

#     tmpl = template_from_str(tmpl_str)
#     assert tmpl.render(fwd=val) == lua
