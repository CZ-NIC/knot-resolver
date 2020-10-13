-- SPDX-License-Identifier: GPL-3.0-or-later

-- do not attempt to contact outside world, operate only on cache
net.ipv4 = false
net.ipv6 = false
-- do not listen, test is driven by config code
env.KRESD_NO_LISTEN = true

local path = worker.cwd..'/control/'..worker.pid
same(true, net.listen(path, nil, {kind = 'control'}),
	'new control sockets were created so map() can work')

modules.load('hints > iterate')
modules.load('daf')

hints['pass.'] = '127.0.0.1'
hints['deny.'] = '127.0.0.1'
hints['deny.'] = '127.0.0.1'
hints['drop.'] = '127.0.0.1'
hints['del.'] = '127.0.0.1'
hints['del2.'] = '127.0.0.1'
hints['toggle.'] = '127.0.0.1'

local check_answer = require('test_utils').check_answer

local function test_sanity()
	check_answer('daf sanity (no rules)', 'pass.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf sanity (no rules)', 'deny.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf sanity (no rules)', 'drop.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf sanity (no rules)', 'del.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf sanity (no rules)', 'del2.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf sanity (no rules)', 'toggle.', kres.type.A, kres.rcode.NOERROR)
end

local function test_basic_actions()
	daf.add('qname = pass. pass')
	daf.add('qname = deny. deny')
	daf.add('qname = drop. drop')

	check_answer('daf pass action', 'pass.', kres.type.A, kres.rcode.NOERROR)
	check_answer('daf deny action', 'deny.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('daf drop action', 'drop.', kres.type.A, kres.rcode.SERVFAIL)
end

local function test_del()
	-- first matching rule is used
	local first = daf.add('qname = del. deny')
	local second = daf.add('qname = del2. deny')

	check_answer('daf del - first rule active',
		'del.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('daf del - second rule active',
		'del2.', kres.type.A, kres.rcode.NXDOMAIN)
	daf.del(first.rule.id)
	check_answer('daf del - first rule deleted',
		'del.', kres.type.A, kres.rcode.NOERROR)
	daf.del(second.rule.id)
	check_answer('daf del - second rule deleted',
		'del2.', kres.type.A, kres.rcode.NOERROR)
end

local function test_toggle()
	local toggle = daf.add('qname = toggle. deny')

	check_answer('daf - toggle active',
		'toggle.', kres.type.A, kres.rcode.NXDOMAIN)
	daf.disable(toggle.rule.id)
	check_answer('daf - toggle disabled',
		'toggle.', kres.type.A, kres.rcode.NOERROR)
	daf.enable(toggle.rule.id)
	check_answer('daf - toggle enabled',
		'toggle.', kres.type.A, kres.rcode.NXDOMAIN)
end

return {
	test_sanity,  -- must be first, expects no daf rules
	test_basic_actions,
	test_del,
	test_toggle,
}
