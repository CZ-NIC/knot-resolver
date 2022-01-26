-- SPDX-License-Identifier: GPL-3.0-or-later
local kr_table_len = require('kluautil').kr_table_len

local function test_env_no_listen()
	-- config tests are executed with env variable KRESD_NO_LISTEN=1
	-- so net.list() should be an empty table
	same(kr_table_len(net.list()), 0,
		"env 'KRESD_NO_LISTEN=1' prevents kresd from listening")
end

local function test_freebind()
	boom(net.listen, {'192.0.2.1', 50049},
		'net.listen() without freebind should fail')
	-- TODO: same(kr_table_len(net.list()), 0,
	-- 	"net.listen() failure does not modify output from net.list()")
	ok(net.listen('192.0.2.1', 50049, { freebind=true }),
		'net.listen() with freebind succeeds')
	local net_list = net.list()
	-- same(list length == 2)
	same(net_list[1].transport.protocol, 'udp',
		'net.listen({freebind = true}) without kind starts UDP listener')
	same(net_list[2].transport.protocol, 'tcp',
		'net.listen({freebind = true}) without kind starts TCP listener')
	same(net_list[1].transport.freebind, true,
		'net.listen({freebind = true}) enables FREEBIND for UDP listener')
	same(net_list[2].transport.freebind, true,
		'net.listen({freebind = true}) enables FREEBIND for TCP listener')
end

local function test_proxy_allowed()
	same(net.proxy_allowed(), {}, 'net.proxy_allowed() empty by default')
	net.proxy_allowed('172.22.0.1')
	same(net.proxy_allowed(), {'172.22.0.1/32'}, 'net.proxy_allowed() single IPv4 host')
	net.proxy_allowed({'172.22.0.1'})
	same(net.proxy_allowed(), {'172.22.0.1/32'}, 'net.proxy_allowed() single IPv4 host (as table)')
	net.proxy_allowed('172.18.1.0/24')
	same(net.proxy_allowed(), {'172.18.1.0/24'}, 'net.proxy_allowed() IPv4 net')
	net.proxy_allowed({'172.22.0.1', '172.18.1.0/24'})
	same(net.proxy_allowed(), {'172.18.1.0/24', '172.22.0.1/32'}, 'net.proxy_allowed() multiple IPv4 args as table')
	net.proxy_allowed({})
	same(net.proxy_allowed(), {}, 'net.proxy_allowed() clear table')
	net.proxy_allowed({'::1'})
	same(net.proxy_allowed(), {'::1/128'}, 'net.proxy_allowed() single IPv6 host')
	net.proxy_allowed({'2001:db8:cafe:beef::/64'})
	same(net.proxy_allowed(), {'2001:db8:cafe:beef::/64'}, 'net.proxy_allowed() IPv6 net')
	net.proxy_allowed({'0.0.0.0/0', '::/0'})
	same(net.proxy_allowed(), {'0.0.0.0/0', '::/0'}, 'net.proxy_allowed() allow all IPv4 and IPv6')
	same(net.proxy_allowed(), {'::1/128'}, 'net.proxy_allowed() single IPv6 host')
	boom(net.proxy_allowed, {'a'}, 'net.proxy_allowed() invalid string arg')
	boom(net.proxy_allowed, {'127.0.0.'}, 'net.proxy_allowed() incomplete IPv4')
	boom(net.proxy_allowed, {'256.0.0.0'}, 'net.proxy_allowed() invalid IPv4')
	boom(net.proxy_allowed, {'xx::'}, 'net.proxy_allowed() invalid IPv6')
	boom(net.proxy_allowed, {'127.0.0.1/33'}, 'net.proxy_allowed() IPv4 invalid netmask')
	boom(net.proxy_allowed, {'127.0.0.1/-1'}, 'net.proxy_allowed() IPv4 negative netmask')
	boom(net.proxy_allowed, {'fd::/132'}, 'net.proxy_allowed() IPv6 invalid netmask')
	boom(net.proxy_allowed, {{'127.0.0.0/8', '::1/129'}}, 'net.proxy_allowed() single param invalid')
end

return {
	test_env_no_listen,
	test_freebind,
	test_proxy_allowed,
}
