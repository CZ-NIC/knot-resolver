local function gen_rrset(owner, rrtype, rdataset)
	local rrset = kres.rrset(todname(owner), rrtype, kres.class.IN, 3600)
	assert(type(rdataset) == 'table' or type(rdataset) == 'string')
	if type(rdataset) ~= 'table' then
		rdataset = { rdataset }
	end
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

	assert(c:insert(gen_rrset('a10.test.', kres.type.A, '\10\0\0\1'),
		nil, ffi.C.KR_RANK_SECURE + ffi.C.KR_RANK_AUTH))

	c:commit()
end

local check_answer = require('test_utils').check_answer

local function test_rpz()
	check_answer('"CNAME rpz-passthru" return A rrset',
		'a10.test.', kres.type.A, kres.rcode.NOERROR, '10.0.0.1')
	check_answer('two AAAA records',
		'two.records.', kres.type.AAAA, kres.rcode.NOERROR,
		{'2001:db8::2', '2001:db8::1'})
end

net.ipv4 = false
net.ipv6 = false

prepare_cache()

return {
	test_renumber,
}
