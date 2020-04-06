
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

local function rrset_to_texts(rr)
	local rr_text = {}
	for w in rr:txt_dump():gmatch("%S+") do table.insert(rr_text, w) end
	return rr_text
end

local function check_answer(desc, qname, qtype, expected_rcode, expected_rdata)
	qtype_str = kres.tostring.type[qtype]
	callback = function(pkt)
		same(pkt:rcode(), expected_rcode,
			desc .. ': expecting answer for query ' .. qname .. ' ' .. qtype_str
			.. ' with rcode ' .. kres.tostring.rcode[expected_rcode])

		if expected_rdata then
			rr_text = rrset_to_texts(pkt:rrsets(kres.section.ANSWER)[1])
			ok(rr_text[4] == expected_rdata,
				desc ..': checking rdata of answer for ' .. qname .. ' ' .. qtype_str)
		else
			-- check empty section
			ok(pkt:rrsets(kres.section.ANSWER)[1] == nil,
				desc ..': checking empty answer section for ' .. qname .. ' ' .. qtype_str)
		end

	end

	resolve(qname, qtype, kres.class.IN, {}, callback)
end

local function test_rpz()
	check_answer('"CNAME ." return NXDOMAIN',
		'nxdomain.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('"CNAME *." return NXDOMAIN',
		'nodata.', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('"CNAME rpz-drop." be dropped',
		'rpzdrop.', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('"CNAME rpz-passthru" return A rrset',
		'rpzpassthru.', kres.type.A, kres.rcode.NOERROR, '127.0.0.9')
	check_answer('"A 192.168.55.5" return local A rrset',
		'rra.', kres.type.A, kres.rcode.NOERROR, '192.168.55.5')
	check_answer('"A 192.168.66.6" with suffixed zone name in owner return local A rrset',
		'rra-zonename-suffix.', kres.type.A, kres.rcode.NOERROR, '192.168.66.6')
	check_answer('non existing AAAA on rra domain return NODATA',
		'rra.', kres.type.AAAA, kres.rcode.NOERROR)
end

net.ipv4 = false
net.ipv6 = false

prepare_cache()

policy.add(policy.rpz(policy.DENY, 'policy.test.rpz'))

return {
	test_rpz,
}
