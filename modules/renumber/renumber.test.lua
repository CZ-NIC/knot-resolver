local function gen_rrset(owner, rrtype, rdataset)
	assert(type(rdataset) == 'table' or type(rdataset) == 'string')
	if type(rdataset) ~= 'table' then
		rdataset = { rdataset }
	end
	local rrset = kres.rrset(todname(owner), rrtype, kres.class.IN, 3600)
	for _, rdata in pairs(rdataset) do
		assert(rrset:add_rdata(rdata, #rdata))
	end
	return rrset
end

local function prepare_cache()
	cache.open(100*MB)
	cache.clear()

	local ffi = require('ffi')
	local c = kres.context().cache

	assert(c:insert(
		gen_rrset('a10-0.test.',
			kres.type.A, kres.str2ip('10.0.0.1')),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('a10-2.test.',
			kres.type.A, kres.str2ip('10.2.0.1')),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('a10-0plus2.test.',
			kres.type.A, {
				kres.str2ip('10.0.0.1'),
				kres.str2ip('10.2.0.1')
			}),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('a10-3plus4.test.',
			kres.type.A, {
				kres.str2ip('10.3.0.1'),
				kres.str2ip('10.4.0.1')
			}),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('a166-66.test.',
			kres.type.A, kres.str2ip('166.66.42.123')),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('a167-81.test.',
			kres.type.A, kres.str2ip('167.81.254.221')),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))
	assert(c:insert(
		gen_rrset('aaaa-db8-1.test.',
			kres.type.AAAA, {
				kres.str2ip('2001:db8:1::1'),
				kres.str2ip('2001:db8:1::2'),
			}),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))

	c:commit()
end

local check_answer = require('test_utils').check_answer

local function test_renumber()
	check_answer('unknown IPv4 range passes through unaffected',
		'a10-0.test.', kres.type.A, kres.rcode.NOERROR, '10.0.0.1')
	check_answer('known IPv4 range is remapped when matching first-defined rule',
		'a10-2.test.', kres.type.A, kres.rcode.NOERROR, '192.168.2.1')
	check_answer('mix of known and unknown IPv4 ranges is remapped correctly',
		'a10-0plus2.test.', kres.type.A, kres.rcode.NOERROR, {'192.168.2.1', '10.0.0.1'})
	check_answer('mix of known and unknown IPv4 ranges is remapped correctly to exact address',
		'a10-3plus4.test.', kres.type.A, kres.rcode.NOERROR, {'10.3.0.1', '192.168.3.10'})
	check_answer('known IPv4 range is remapped when matching second-defined rule',
		'a166-66.test.', kres.type.A, kres.rcode.NOERROR, '127.0.42.123')
	check_answer('known IPv4 range is remapped when matching a rule with netmask not on a byte boundary',
		'a167-81.test.', kres.type.A, kres.rcode.NOERROR, {'127.0.30.221'})

	check_answer('two AAAA records',
		'aaaa-db8-1.test.', kres.type.AAAA, kres.rcode.NOERROR,
		{'2001:db8:2::2', '2001:db8:2::1'})
end

net.ipv4 = false
net.ipv6 = false

trust_anchors.remove('.')
policy.add(policy.all(policy.DEBUG_ALWAYS))
policy.add(policy.suffix(policy.PASS, {todname('test.')}))
prepare_cache()

log_level('debug')
modules.load('renumber < cache')
renumber.config({
	-- Source subnet, destination subnet
	{'10.2.0.0/24', '192.168.2.0'},
	{'10.4.0.0/24', '192.168.3.10!'},
	{'166.66.0.0/16', '127.0.0.0'},
	{'167.81.255.0/19', '127.0.0.0'},
	{'2001:db8:1::/48', '2001:db8:2::'},
})

return {
	test_renumber,
}
