
policy.add(policy.rpz(policy.DENY, 'policy.test.rpz'))

local function parse_rrset(rr)
	local rr_dump = {}
	for w in rr:txt_dump():gmatch("%S+") do table.insert(rr_dump, w) end
	return rr_dump
end

local function check_answer(desc, qname, qtype, expected_rcode, expected_rdata)
	qtype_str = kres.tostring.type[qtype]
	callback = function(pkt)
		same(pkt:rcode(), expected_rcode,
			desc .. ': expecting answer for query ' .. qname .. ' ' .. qtype_str
			.. ' with rcode ' .. kres.tostring.rcode[expected_rcode])

		if expected_rdata then
			if expected_rdata == '' then
				-- check empty section
				ok(pkt:rrsets(kres.section.ANSWER)[1] == nil,
					desc ..': checking empty answer section for ' .. qname .. ' ' .. qtype_str)
			else
				rr_dump = parse_rrset(pkt:rrsets(kres.section.ANSWER)[1])
				ok(rr_dump[4] == expected_rdata,
					desc ..': checking rdata of answer for ' .. qname .. ' ' .. qtype_str)
			end
		end

	end

	resolve(qname, qtype, kres.class.IN, {}, callback)
end

local function test_rpz()
	check_answer('\"example.cz CNAME .\" return NXDOMAIN',
		'example.cz', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('\"*.example.cz CNAME *.\" return NXDOMAIN',
		'www.example.cz', kres.type.A, kres.rcode.NXDOMAIN)
	check_answer('\"nic.cz CNAME .\" be dropped',
		'nic.cz', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('\"example.com CNAME rpz-passthru\" return A rrset',
		'example.com', kres.type.A, kres.rcode.NOERROR)
	check_answer('\"example2.cz A 192.168.55.5\" return local A rrset',
		'example2.cz', kres.type.A, kres.rcode.NOERROR, '192.168.55.5')
	check_answer('non existing AAAA on example2.cz return NODATA',
		'example2.cz', kres.type.AAAA, kres.rcode.NOERROR, '')
	check_answer('unsupported \"example2.cz CNAME local.dname\" return NODATA',
		'example2.cz', kres.type.CNAME, kres.rcode.NOERROR, '')
end

return {
	test_rpz,
}
