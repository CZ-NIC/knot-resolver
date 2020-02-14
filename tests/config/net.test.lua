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

return {
	test_env_no_listen,
	test_freebind,
}
