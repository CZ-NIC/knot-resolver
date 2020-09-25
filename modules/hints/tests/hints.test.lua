-- SPDX-License-Identifier: GPL-3.0-or-later
local utils = require('test_utils')

-- setup resolver
modules = { 'hints' }

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

return {
	test_default,
	test_custom
}
