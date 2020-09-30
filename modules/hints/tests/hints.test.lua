-- SPDX-License-Identifier: GPL-3.0-or-later
local utils = require('test_utils')

-- setup resolver
modules = { 'hints > iterate' }

-- test for default configuration
local function test_default()
	-- get loaded root hints and change names to lowercase
	local hints_data = utils.table_keys_to_lower(hints.root())

	-- root hints loaded from default location
	-- check correct ip address of a.root-server.net
	utils.contains(hints_data['a.root-servers.net.'], '198.41.0.4', 'has IP address for a.root-servers.net.')
end

-- test loading from config file
local function test_custom()
	-- load custom root hints file with fake ip address for a.root-server.net
	local err_msg = hints.root_file('hints_test.zone')
	same(err_msg, '', 'load root hints from file')

	-- get loaded root hints and change names to lowercase
	local hints_data = utils.table_keys_to_lower(hints.root())
	isnt(hints_data['a.root-servers.net.'], nil, 'can retrieve root hints')

	-- check loaded ip address of a.root-server.net
	utils.not_contains(hints_data['a.root-servers.net.'], '198.41.0.4',
		'real IP address for a.root-servers.net. is replaced')
	utils.contains(hints_data['a.root-servers.net.'], '10.0.0.1',
		'real IP address for a.root-servers.net. is correct')
end

-- test that setting an address hint works (TODO: and NXDOMAIN)
local function test_nxdomain()
	hints.config() -- clean start
	hints.use_nodata(false)
	hints['myname.lan'] = '192.0.2.1'
	-- TODO: prefilling or some other way of getting NXDOMAIN (instead of SERVFAIL)
	utils.check_answer('bad name gives NXDOMAIN',
		'badname.lan', kres.type.A, kres.rcode.SERVFAIL)
	utils.check_answer('another type gives NXDOMAIN',
		'myname.lan', kres.type.AAAA, kres.rcode.SERVFAIL)
	utils.check_answer('record itself is OK',
		'myname.lan', kres.type.A, kres.rcode.NOERROR)
end

-- test that NODATA is correctly generated
local function test_nodata()
	hints.config() -- clean start
	hints.use_nodata(true) -- default ATM but let's not depend on that
	hints['myname.lan'] = '2001:db8::1'
	utils.check_answer('another type gives NODATA',
		'myname.lan', kres.type.MX, utils.NODATA)
	utils.check_answer('record itself is OK',
		'myname.lan', kres.type.AAAA, kres.rcode.NOERROR)
end

return {
	test_default,
	test_custom,
	test_nxdomain,
	test_nodata,
}
