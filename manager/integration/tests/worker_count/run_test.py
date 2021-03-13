


import requests
import requests_unixsocket
import subprocess
import time

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
PAYLOAD_F = lambda num: f"""
num_workers: {num}
lua_config: |
{ PREPROCESSED_CONFIG }"""

def set_workers(num: int):
	# send the config
	r = requests.post('http+unix://%2Ftmp%2Fmanager.sock/config', data=PAYLOAD_F(num))
	r.raise_for_status()

def count_running() -> int:
	cmd = subprocess.run("ps aux | grep kresd | grep -v grep", shell=True, stdout=subprocess.PIPE)
	return len(str(cmd.stdout, 'utf8').strip().split("\n"))


print("Initial 1 worker config...")
set_workers(1)
time.sleep(1)
count = count_running()
assert count == 1, f"Unexpected number of kresd instances is running - {count}"

print("Increasing worker count to 8")
set_workers(8)
time.sleep(2)
count = count_running()
assert count == 8, f"Unexpected number of kresd instances is running - {count}"

print("Decreasing worker count to 4")
set_workers(4)
time.sleep(2)
count = count_running()
assert count == 4, f"Unexpected number of kresd instances is running - {count}"