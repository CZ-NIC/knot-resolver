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

	c:commit()
end

local check_answer = require('test_utils').check_answer

local function prefix_matches(bits, prefix, val)
end

local function test_renumber()
	check_answer('unknown IPv4 range passes through unaffected',
		'a10-0.test.', kres.type.A, kres.rcode.NOERROR, '10.0.0.1')
	check_answer('known IPv4 range is remapped',
		'a10-2.test.', kres.type.A, kres.rcode.NOERROR, '192.168.2.1')
	check_answer('mix of known and unknown IPv4 ranges is remapped correctly',
		'a10-0plus2.test.', kres.type.A, kres.rcode.NOERROR, {'192.168.2.1', '10.0.0.1'})


--	check_answer('two AAAA records',
--		'two.records.', kres.type.AAAA, kres.rcode.NOERROR,
--		{'2001:db8::2', '2001:db8::1'})
end

net.ipv4 = false
net.ipv6 = false

trust_anchors.remove('.')
policy.add(policy.all(policy.DEBUG_ALWAYS))
policy.add(policy.suffix(policy.PASS, {todname('test.')}))
prepare_cache()

verbose(true)
modules.load('renumber < cache')
renumber.config({
	-- Source subnet, destination subnet
	{'10.2.0.0/24', '192.168.2.0'},
	{'166.66.0.0/16', '127.0.0.0'}
})

return {
	test_renumber,
}
