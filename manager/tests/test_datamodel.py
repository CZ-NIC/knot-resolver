from knot_resolver_manager.datamodel import KresConfig


def test_simple():
    json = """
    {
    "server": {
        "instances": 1
    },
    "lua": {
        "script_list": [
        "-- SPDX-License-Identifier: CC0-1.0",
        "-- vim:syntax=lua:set ts=4 sw=4:",
        "-- Refer to manual: https://knot-resolver.readthedocs.org/en/stable/",
        "-- Network interface configuration","net.listen('127.0.0.1', 53, { kind = 'dns' })",
        "net.listen('127.0.0.1', 853, { kind = 'tls' })",
        "--net.listen('127.0.0.1', 443, { kind = 'doh2' })",
        "net.listen('::1', 53, { kind = 'dns', freebind = true })",
        "net.listen('::1', 853, { kind = 'tls', freebind = true })",
        "--net.listen('::1', 443, { kind = 'doh2' })",
        "-- Load useful modules","modules = {",
        "'hints > iterate',  -- Load /etc/hosts and allow custom root hints",
        "'stats',            -- Track internal statistics",
        "'predict',          -- Prefetch expiring/frequent records",
        "}",
        "-- Cache size",
        "cache.size = 100 * MB"
        ]
    }
    }
    """

    config = KresConfig.from_json(json)

    assert config.server.instances == 1
    assert config.lua.script is not None
