local basexx = require('basexx')
local ffi = require('ffi')

local function gen_huge_answer(_, req)
	local qry = req:current()
	local answer = req.answer
	ffi.C.kr_pkt_make_auth_header(answer)

	answer:rcode(kres.rcode.NOERROR)

	-- 64k answer
	answer:begin(kres.section.ANSWER)
	answer:put('\4test\0', 300, answer:qclass(), kres.type.URI,
		'\0\0\0\0' .. string.rep('0', 65000))
	answer:put('\4test\0', 300, answer:qclass(), kres.type.URI,
		'\0\0\0\0' .. 'done')
	return kres.DONE
end

local function gen_varying_ttls(_, req)
	local qry = req:current()
	local answer = req.answer
	ffi.C.kr_pkt_make_auth_header(answer)

	answer:rcode(kres.rcode.NOERROR)

	-- varying TTLs in ANSWER section
	answer:begin(kres.section.ANSWER)
	answer:put(qry.sname, 1800, answer:qclass(), kres.type.AAAA,
		'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
	answer:put(qry.sname, 900, answer:qclass(), kres.type.A, '\127\0\0\1')
	answer:put(qry.sname, 20000, answer:qclass(), kres.type.NS, '\2ns\4test\0')

	-- shorter TTL than all other RRs
	answer:begin(kres.section.AUTHORITY)
	answer:put('\4test\0', 300, answer:qclass(), kres.type.SOA,
		'\2ns\4test\0\6nobody\7invalid\0\0\0\0\1\0\0\14\16\0\0\4\176\0\9\58\128\0\0\42\48')
	return kres.DONE
end

function parse_pkt(input, desc)
	local wire = ffi.cast("void *", input)
	local pkt = ffi.C.knot_pkt_new(wire, #input, nil);
	assert(pkt, desc .. ': failed to create new packet')

	local result = ffi.C.knot_pkt_parse(pkt, 0)
	ok(result == 0, desc .. ': knot_pkt_parse works on received answer')
	return pkt
end

local function check_ok(req, desc)
	local headers, stream, errno = req:go(8)  -- randomly chosen timeout by tkrizek
	if errno then
		local errmsg = stream
		nok(errmsg, desc .. ': ' .. errmsg)
		return
	end
	same(tonumber(headers:get(':status')), 200, desc .. ': status 200')
	same(headers:get('content-type'), 'application/dns-message', desc .. ': content-type')
	local body = assert(stream:get_body_as_string())
	local pkt = parse_pkt(body, desc)
	return headers, pkt
end

local function check_err(req, exp_status, desc)
	local headers, errmsg, errno = req:go(8)  -- randomly chosen timeout by tkrizek
	if errno then
		nok(errmsg, desc .. ': ' .. errmsg)
		return
	end
	local got_status = headers:get(':status')
	same(got_status, exp_status, desc)
end

-- check prerequisites
local has_http = pcall(require, 'kres_modules.http') and pcall(require, 'http.request')
if not has_http then
	pass('skipping http module test because its not installed')
	done()
else
	local request = require('http.request')
	local endpoints = require('kres_modules.http').endpoints

	-- setup resolver
	modules = {
		http = {
			port = 0, -- Select random port
			cert = false,
			endpoints = endpoints,
		}
	}
	policy.add(policy.suffix(policy.DROP, policy.todnames({'servfail.test.'})))
	policy.add(policy.suffix(policy.DENY, policy.todnames({'nxdomain.test.'})))
	policy.add(policy.suffix(gen_varying_ttls, policy.todnames({'noerror.test.'})))

	local server = http.servers[1]
	ok(server ~= nil, 'creates server instance')
	local _, host, port = server:localname()
	ok(host and port, 'binds to an interface')
	local uri_templ = string.format('http://%s:%d/doh', host, port)
	local req_templ = assert(request.new_from_uri(uri_templ))
	req_templ.headers:upsert('content-type', 'application/dns-message')

	-- test a valid DNS query using POST
	local function test_doh_servfail()
		local desc = 'valid POST query which ends with SERVFAIL'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- servfail.test. A
			'FZUBAAABAAAAAAAACHNlcnZmYWlsBHRlc3QAAAEAAQ=='))
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		-- uncacheable
		same(headers:get('cache-control'), 'max-age=0', desc .. ': TTL 0')
		same(pkt:rcode(), kres.rcode.SERVFAIL, desc .. ': rcode matches')
	end

	local function test_doh_noerror()
		local desc = 'valid POST query which ends with NOERROR'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns='  -- noerror.test. A
			.. 'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		-- HTTP TTL is minimum from all RRs in the answer
		same(headers:get('cache-control'), 'max-age=300', desc .. ': TTL 900')
		same(pkt:rcode(), kres.rcode.NOERROR, desc .. ': rcode matches')
		same(pkt:ancount(), 3, desc .. ': ANSWER is present')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
		same(pkt:arcount(), 0, desc .. ': ADDITIONAL is empty')
	end

	local function test_doh_nxdomain()
		local desc = 'valid POST query which ends with NXDOMAIN'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- servfail.test. A
			'viABAAABAAAAAAAACG54ZG9tYWluBHRlc3QAAAEAAQ=='))
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		same(headers:get('cache-control'), 'max-age=10800', desc .. ': TTL 10800')
		same(pkt:rcode(), kres.rcode.NXDOMAIN, desc .. ': rcode matches')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
	end


	local function test_unsupp_method()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'PUT')
		check_err(req, '405', 'unsupported method finishes with 405')
	end

	local function test_post_short_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req:set_body(string.rep('0', 11))  -- 11 bytes < DNS msg header
		check_err(req, '400', 'too short POST finishes with 400')
	end

	local function test_post_long_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req:set_body(string.rep('s', 1025))  -- > DNS msg over UDP
		check_err(req, '413', 'too long POST finishes with 413')
	end

	local function test_get_long_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns=' .. basexx.to_url64(string.rep('\0', 1030)))
		check_err(req, '414', 'too long GET finishes with 414')
	end

	local function test_post_unparseable_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req:set_body(string.rep('\0', 1024))  -- garbage
		check_err(req, '400', 'unparseable DNS message finishes with 400')
	end

	local function test_post_unsupp_type()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req.headers:upsert('content-type', 'application/dns+json')
		req:set_body(string.rep('\0', 12))  -- valid message
		check_err(req, '415', 'unsupported request content type finishes with 415')
	end

	local function test_dstaddr()
		local triggered = false
		local exp_dstaddr = ffi.gc(ffi.C.kr_straddr_socket(host, port), ffi.C.free)
		local function check_dstaddr(state, req)
			triggered = true
			same(ffi.C.kr_sockaddr_cmp(req.qsource.dst_addr, exp_dstaddr), 0,
				'request has correct server address')
			return state
		end
		policy.add(policy.suffix(check_dstaddr, policy.todnames({'dstaddr.test'})))
		local desc = 'valid POST query has server address available in request'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- dstaddr.test. A
			'FnkBAAABAAAAAAAAB2RzdGFkZHIEdGVzdAAAAQAB'))
		check_ok(req, desc)
		ok(triggered, 'dstaddr policy was triggered')
	end

	local function test_srcaddr()
		modules.load('view')
		assert(view)
		local policy_refuse = policy.suffix(policy.REFUSE, policy.todnames({'srcaddr.test.knot-resolver.cz'}))
		-- these netmasks would not work if the request did not contain IP addresses
		view:addr('0.0.0.0/0', policy_refuse)
		view:addr('::/0', policy_refuse)

		local desc = 'valid POST query has source address available in request'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- srcaddr.test.knot-resolver.cz TXT
			'QNQBAAABAAAAAAAAB3NyY2FkZHIEdGVzdA1rbm90LXJlc29sdmVyAmN6AAAQAAE'))
		local headers, pkt = check_ok(req, desc)
		same(pkt:rcode(), kres.rcode.REFUSED, desc .. ': view module caught it')

		modules.unload('view')
	end

	-- RFC 8484 section 6 explicitly allows huge answers over HTTP
	local function test_huge_answer()
		local triggered = false
		policy.add(policy.suffix(gen_huge_answer, policy.todnames({'huge.test'})))
		local desc = 'POST query for a huge answer'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- huge.test. URI, no EDNS
			'HHwBAAABAAAAAAAABGh1Z2UEdGVzdAABAAAB'))
		local headers, pkt = check_ok(req, desc)
		same(pkt:rcode(), kres.rcode.NOERROR, desc .. ': rcode NOERROR')
		same(pkt:tc(), false, desc .. ': no TC bit')
		same(pkt:ancount(), 2, desc .. ': ANSWER contains both RRs')
	end

--	not implemented
--	local function test_post_unsupp_accept()
--		local req = assert(req_templ:clone())
--		req.headers:upsert(':method', 'POST')
--		req.headers:upsert('accept', 'application/dns+json')
--		req:set_body(string.rep('\0', 12))  -- valid message
--		check_err(req, '406', 'unsupported Accept type finishes with 406')
--	end

	-- plan tests
	local tests = {
		test_unsupp_method,
		test_post_short_input,
		test_post_long_input,
		test_get_long_input,
		test_post_unparseable_input,
		test_post_unsupp_type,
		test_doh_servfail,
		test_doh_nxdomain,
		test_doh_noerror,
		test_dstaddr,
		test_srcaddr,
		test_huge_answer
	}

	return tests
end
