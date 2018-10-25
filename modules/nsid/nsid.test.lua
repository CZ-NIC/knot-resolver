-- disable networking so we can get SERVFAIL immediatelly
net.ipv4 = false
net.ipv6 = false

local function check_answer_nsid(desc, expected_rcode)
	callback = function(pkt)
		same(pkt:rcode(), expected_rcode, desc)

		ok((pkt:ancount() > 0) == (pkt:rcode() == kres.rcode.NOERROR),
		   desc ..': checking number of answers for ' .. qname .. ' ' .. qtype_str)
	end
	resolve(qname, qtype, kres.class.IN, {}, callback)
end

-- test for nsid.name() interface
local function test_nsid_name()
	if nsid then
		modules.unload('nsid')
	end
	modules.load('nsid')
	same(nsid.name(), nil, 'NSID modes not provide default NSID value')
	same(nsid.name('123456'), '123456', 'NSID value can be changed')
	same(nsid.name(), '123456', 'NSID module remembers configured NSID value')
	modules.unload('nsid')
	modules.load('nsid')
	same(nsid.name(), nil, 'NSID module reload removes configured value')
end

return {
	test_nsid_name,

}
