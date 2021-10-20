
local function prepare_cache()
	cache.open(100*MB)
	cache.clear()

	local ffi = require('ffi')
	local c = kres.context().cache

	local passthru_addr = '\127\0\0\9'
	rr_passthru = kres.rrset(todname('rpzpassthru.'), kres.type.A, kres.class.IN, 3600999999)
	assert(rr_passthru:add_rdata(passthru_addr, #passthru_addr))
	assert(c:insert(rr_passthru, nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))

	c:commit()
end

local check_answer = require('test_utils').check_answer

local function test_rpz()
	check_answer('"CNAME ." return NXDOMAIN',
		'nxdomain.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('"CNAME *." return NODATA',
		'nodata.', kres.type.A, kres.rcode.NOERROR, {})
	check_answer('"CNAME *. on wildcard" return NODATA',
		'nodata.nxdomain.', kres.type.A, kres.rcode.NOERROR, {})
	check_answer('"CNAME rpz-drop." be dropped',
		'rpzdrop.', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('"CNAME rpz-passthru" return A rrset',
		'rpzpassthru.', kres.type.A, kres.rcode.NOERROR, '127.0.0.9')
	check_answer('"A 192.168.5.5" return local A rrset',
		'rra.', kres.type.A, kres.rcode.NOERROR, '192.168.5.5')
	check_answer('"A 192.168.6.6" with suffixed zone name in owner return local A rrset',
		'rra-zonename-suffix.', kres.type.A, kres.rcode.NOERROR, '192.168.6.6')
	check_answer('"A 192.168.7.7" with suffixed zone name in owner return local A rrset',
		'testdomain.rra.', kres.type.A, kres.rcode.NOERROR, '192.168.7.7')
	check_answer('non existing AAAA on rra domain return NODATA',
		'rra.', kres.type.AAAA, kres.rcode.NOERROR, {})
	check_answer('"A 192.168.8.8" and domain with uppercase and lowercase letters',
		'case.sensitive.', kres.type.A, kres.rcode.NOERROR, '192.168.8.8')
	check_answer('"A 192.168.8.8" and domain with uppercase and lowercase letters',
		'CASe.SENSItivE.', kres.type.A, kres.rcode.NOERROR, '192.168.8.8')
	check_answer('two AAAA records',
		'two.records.', kres.type.AAAA, kres.rcode.NOERROR,
		{'2001:db8::2', '2001:db8::1'})
end

local function test_rpz_soa()
	check_answer('"CNAME ." return NXDOMAIN (SOA origin)',
		'nxdomain-fqdn.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('"CNAME *." return NODATA (SOA origin)',
		'nodata-fqdn.', kres.type.A, kres.rcode.NOERROR, {})
end

net.ipv4 = false
net.ipv6 = false

prepare_cache()

policy.add(policy.rpz(policy.DENY, 'policy.test.rpz'))
policy.add(policy.rpz(policy.DENY, 'policy.test.rpz.soa'))

return {
	test_rpz,
	test_rpz_soa,
}
