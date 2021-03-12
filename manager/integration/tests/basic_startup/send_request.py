


import requests
import requests_unixsocket

# patch requests library so that it supports unix socket
requests_unixsocket.monkeypatch()

# prepare the payload
LUA_CONFIG = """
-- SPDX-License-Identifier: CC0-1.0
-- vim:syntax=lua:set ts=4 sw=4:
-- Refer to manual: https://knot-resolver.readthedocs.org/en/stable/

-- Network interface configuration
net.listen('127.0.0.1', 53, { kind = 'dns' })
net.listen('127.0.0.1', 853, { kind = 'tls' })
--net.listen('127.0.0.1', 443, { kind = 'doh2' })
net.listen('::1', 53, { kind = 'dns', freebind = true })
net.listen('::1', 853, { kind = 'tls', freebind = true })
--net.listen('::1', 443, { kind = 'doh2' })

-- Load useful modules
modules = {
	'hints > iterate',  -- Load /etc/hosts and allow custom root hints
	'stats',            -- Track internal statistics
	'predict',          -- Prefetch expiring/frequent records
}

-- Cache size
cache.size = 100 * MB
"""
PREPROCESSED_CONFIG = "\n  ".join(LUA_CONFIG.splitlines(keepends=False))
PAYLOAD = f"""
num_workers: 4
lua_config: |
{ PREPROCESSED_CONFIG }
"""

# send the config
r = requests.post('http+unix://%2Ftmp%2Fmanager.sock/config', data=PAYLOAD)
r.raise_for_status()