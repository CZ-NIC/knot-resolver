-- SPDX-License-Identifier: GPL-3.0-or-later
local basexx = require('basexx')
local ffi = require('ffi')

local function gen_huge_answer(_, req)
	local answer = req:ensure_answer()
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
	local answer = req:ensure_answer()
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
		-- ns.test. nobody.invalid. 1 3600 1200 604800 10800
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
	local headers, stream, errno = req:go(16)
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
	local headers, errmsg, errno = req:go(16)
	if errno then
		nok(errmsg, desc .. ': ' .. errmsg)
		return
	end
	local got_status = headers:get(':status')
	same(got_status, exp_status, desc)
end

-- check prerequisites
local bound, port
local host = '127.0.0.1'
for _  = 1,10 do
	port = math.random(30000, 39999)
	bound = pcall(net.listen, host, port, { kind = 'doh2'})
	if bound then
		break
	end
end

if not bound then
	-- skipping doh2 tests (failure to bind may be caused by missing support during build)
	os.exit(77)
else
	policy.add(policy.suffix(policy.DROP, policy.todnames({'servfail.test.'})))
	policy.add(policy.suffix(policy.DENY, policy.todnames({'nxdomain.test.'})))
	policy.add(policy.suffix(gen_varying_ttls, policy.todnames({'noerror.test.'})))

	local req_templ, uri_templ
	local function start_server()
		local request = require('http.request')
		local ssl_ctx = require('openssl.ssl.context')
		uri_templ = string.format('https://%s:%d/dns-query', host, port)
		req_templ = assert(request.new_from_uri(uri_templ))
		req_templ.headers:upsert('content-type', 'application/dns-message')
		req_templ.ctx = ssl_ctx.new()
		req_templ.ctx:setVerify(ssl_ctx.VERIFY_NONE)
	end


	-- test a valid DNS query using POST
	local function test_post_servfail()
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
		same(headers:get('access-control-allow-origin'), '*', desc .. ': CORS headers')
		same(pkt:rcode(), kres.rcode.SERVFAIL, desc .. ': rcode matches')
	end

	local function test_post_noerror()
		local desc = 'valid POST query which ends with NOERROR'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- noerror.test. A
			'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB'))
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

	local function test_post_ignore_params_1()
		local desc = 'valid POST ignores parameters (without ?dns)'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req.headers:upsert(':path', '/doh?something=asdf&aaa=bbb')
		req:set_body(basexx.from_base64(  -- noerror.test. A
			'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB'))
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

	local function test_post_ignore_params_2()
		local desc = 'valid POST ignores parameters (with ?dns)'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req.headers:upsert(':path', '/dns-query?dns='  -- servfail.test. A
			.. 'FZUBAAABAAAAAAAACHNlcnZmYWlsBHRlc3QAAAEAAQ')
		req:set_body(basexx.from_base64(  -- noerror.test. A
			'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB'))
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

	local function test_post_nxdomain()
		local desc = 'valid POST query which ends with NXDOMAIN'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- nxdomain.test. A
			'viABAAABAAAAAAAACG54ZG9tYWluBHRlc3QAAAEAAQ=='))
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		same(headers:get('cache-control'), 'max-age=10800', desc .. ': TTL 10800')
		same(pkt:rcode(), kres.rcode.NXDOMAIN, desc .. ': rcode matches')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
	end

	-- RFC 8484 section 6 explicitly allows huge answers over HTTP
	local function test_huge_answer()
		policy.add(policy.suffix(gen_huge_answer, policy.todnames({'huge.test'})))
		local desc = 'POST query for a huge answer'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'POST')
		req:set_body(basexx.from_base64(  -- huge.test. URI, no EDNS
			'HHwBAAABAAAAAAAABGh1Z2UEdGVzdAABAAAB'))
		local _, pkt = check_ok(req, desc)
		same(pkt:rcode(), kres.rcode.NOERROR, desc .. ': rcode NOERROR')
		same(pkt:tc(), false, desc .. ': no TC bit')
		same(pkt:ancount(), 2, desc .. ': ANSWER contains both RRs')
	end

	-- test an invalid DNS query using POST
	local function test_post_short_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req:set_body(string.rep('0', 11))  -- 11 bytes < DNS msg header
		check_err(req, '400', 'too short POST finishes with 400')
	end

--	local function test_post_long_input()
--		-- FIXME: This test is broken in Lua. The connection times out
--		-- for some reason, but sending a request like this with `curl`
--		-- or PowerShell's `Invoke-RestMethod` provides correct results.
--
--		local req = assert(req_templ:clone())
--		req.headers:upsert(':method', 'POST')
--		req:set_body(string.rep('s', 1025))  -- > DNS msg over UDP
--		check_err(req, '400', 'too long POST finishes with 400')
--	end

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

	-- test a valid DNS query using GET
	local function test_get_servfail()
		local desc = 'valid GET query which ends with SERVFAIL'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns='  -- servfail.test. A
			.. 'FZUBAAABAAAAAAAACHNlcnZmYWlsBHRlc3QAAAEAAQ')
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		-- uncacheable
		same(headers:get('cache-control'), 'max-age=0', desc .. ': TTL 0')
		same(pkt:rcode(), kres.rcode.SERVFAIL, desc .. ': rcode matches')
	end

	local function test_get_noerror()
		local desc = 'valid GET query which ends with NOERROR'
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
		same(headers:get('access-control-allow-origin'), '*', desc .. ': CORS headers')
		same(pkt:rcode(), kres.rcode.NOERROR, desc .. ': rcode matches')
		same(pkt:ancount(), 3, desc .. ': ANSWER is present')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
		same(pkt:arcount(), 0, desc .. ': ADDITIONAL is empty')
	end

	local function test_get_nxdomain()
		local desc = 'valid GET query which ends with NXDOMAIN'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns='  -- nxdomain.test. A
			.. 'viABAAABAAAAAAAACG54ZG9tYWluBHRlc3QAAAEAAQ')
		local headers, pkt = check_ok(req, desc)
		if not (headers and pkt) then
			return
		end
		same(headers:get('cache-control'), 'max-age=10800', desc .. ': TTL 10800')
		same(pkt:rcode(), kres.rcode.NXDOMAIN, desc .. ': rcode matches')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
	end

	local function test_get_multiple_amps()
		local desc = 'GET query with consecutive ampersands'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path',
		'/doh?other=something&another=something&&&&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		check_ok(req, desc)
	end

	local function test_get_other_params_before_dns()
		local desc = 'GET query with other parameters before dns is valid'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path',
		'/doh?other=something&another=something&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		check_ok(req, desc)
	end

	local function test_get_other_params_after_dns()
		local desc = 'GET query with other parameters after dns is valid'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path',
		'/doh?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB&other=something&another=something')
		check_ok(req, desc)
	end

	local function test_get_other_params()
		local desc = 'GET query with other parameters than dns on both sides is valid'
		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path',
		'/doh?other=something&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB&another=something')
		check_ok(req, desc)
	end

	-- test an invalid DNS query using GET
	local function test_get_long_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns=' .. basexx.to_url64(string.rep('\0', 1030)))
		check_err(req, '400', 'too long GET finishes with 400')
	end

	local function test_get_no_dns_param()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?notdns=' .. basexx.to_url64(string.rep('\0', 1024)))
		check_err(req, '400', 'GET without dns parameter finishes with 400')
	end

	local function test_get_unparseable()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh??dns=' .. basexx.to_url64(string.rep('\0', 1024)))
		check_err(req, '400', 'unparseable GET finishes with 400')
	end

	local function test_get_invalid_b64()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns=thisisnotb64')
		check_err(req, '400', 'GET with invalid base64 finishes with 400')
	end

	local function test_get_invalid_chars()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns=' .. basexx.to_url64(string.rep('\0', 200)) .. '@#$%?!')
		check_err(req, '400', 'GET with invalid characters in b64 finishes with 400')
	end

	local function test_unsupp_method()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'PUT')
		check_err(req, '501', 'unsupported method finishes with 501')
	end

	local function test_dstaddr()
		local triggered = false
		local exp_dstaddr = ffi.gc(ffi.C.kr_straddr_socket(host, port, nil), ffi.C.free)
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
		local _, pkt = check_ok(req, desc)
		same(pkt:rcode(), kres.rcode.REFUSED, desc .. ': view module caught it')

		modules.unload('view')
	end

	local function test_headers()
		local get_desc = nil

		local function check_headers_zero_len(state, req)
			same(tonumber(req.qsource.headers.len), 0, get_desc())
			return state
		end

		local function check_headers_value(state, req)
			local value = ffi.string(req.qsource.headers.at[0].value)
			same(value, 'lua test config.doh2', get_desc())
			return state
		end

		local function check_headers_more_values(state, req)
			local checked = 0
			for i = 1, tonumber(req.qsource.headers.len) do
				local name = ffi.string(req.qsource.headers.at[i - 1].name)
				local value = ffi.string(req.qsource.headers.at[i - 1].value)
				if (name == 'user-agent') then
					same(value, 'lua test config.doh2', get_desc() .. ' - user-agent')
					checked = checked + 1
				elseif (name == ':scheme') then
					same(value, 'https', get_desc() .. ' - :scheme')
					checked = checked + 1
				end
			end

			same(checked, 2, get_desc() .. ' - two checked')
			return state
		end

		local req = req_templ:clone()
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns='  -- headers.test. A
			.. 'AAABAAABAAAAAAAAB2hlYWRlcnMEdGVzdAAAAQAB')
		req.headers:upsert('user-agent', 'lua test config.doh2')
		req.headers:upsert(':scheme', 'https')

		get_desc = function() return 'exposed HTTP headers: no headers' end
		rule_desc = policy.add(policy.all(check_headers_zero_len))
		check_ok(req, get_desc())
		get_desc = function() return 'exposed HTTP headers: empty string' end
		net.doh_headers('')
		check_ok(req, get_desc())
		get_desc = function() return 'exposed HTTP headers: empty table' end
		net.doh_headers({''})
		check_ok(req, get_desc())
		policy.del(rule_desc.id)

		get_desc = function() return 'exposed HTTP headers: take just one string parameter' end
		boom(net.doh_headers, {'user-agent', ':method'}, get_desc())
		get_desc = function() return 'exposed HTTP headers: take just one table parameter' end
		boom(net.doh_headers, {{'user-agent'}, {':method'}}, get_desc())

		get_desc = function() return 'exposed HTTP headers: take one header - as string' end
		net.doh_headers('user-agent')
		rule_desc = policy.add(policy.all(check_headers_value))
		check_ok(req, get_desc())
		get_desc = function() return 'exposed HTTP headers: take one header - as table' end
		net.doh_headers({ 'user-agent' })
		check_ok(req, get_desc())
		policy.del(rule_desc.id)

		get_desc = function() return 'exposed HTTP headers: take more headers' end
		net.doh_headers({ ':method', 'user-agent', ':path', ':scheme' })
		rule_desc = policy.add(policy.all(check_headers_more_values))
		check_ok(req, get_desc())
		policy.del(rule_desc.id)


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
		start_server,
		test_post_servfail,
		test_post_noerror,
		test_post_ignore_params_1,
		test_post_ignore_params_2,
		test_post_nxdomain,
		test_huge_answer,
		test_post_short_input,
--		test_post_long_input, -- FIXME see the test function
		test_post_unparseable_input,
		test_post_unsupp_type,
		test_get_servfail,
		test_get_noerror,
		test_get_nxdomain,
		test_get_multiple_amps,
		test_get_other_params_before_dns,
		test_get_other_params_after_dns,
		test_get_other_params,
		test_get_long_input,
		test_get_no_dns_param,
		test_get_unparseable,
		test_get_invalid_b64,
		test_get_invalid_chars,
		test_unsupp_method,
		test_dstaddr,
		test_srcaddr,
		test_headers
	}

	return tests
end
