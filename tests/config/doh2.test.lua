-- SPDX-License-Identifier: GPL-3.0-or-later
local basexx = require('basexx')
local ffi = require('ffi')
local monotime = require('cqueues').monotime

-- check prerequisites
local timeout = 8 -- randomly chosen timeout by tkrizek
local bound, port
local host = '127.0.0.1'
for _  = 1,10 do
	port = math.random(30000, 39999)
	bound = pcall(net.listen, host, port, { kind = 'doh2'})
	if bound then
		break
	end
end

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

local function non_final_status(status)
	return status:sub(1, 1) == "1" and status ~= "101"
end

local function request_set_body(req, body)
	req['body'] = body
end

local function connection_connect(req)
	local client = require('http.client')
	local err, errno
	req['deadline'] = req['timeout'] and (monotime()+req['timeout'])

	connection, err, errno = client.connect({
		host = host;
		port = port;
		tls = true;
		ctx = req['ctx'];
		version = 2;
		h2_settings = { ENABLE_PUSH = false; };
	}, req['deadline'] and req['deadline']-monotime())
	if connection == nil then
		print('Connection error ' .. err .. ': ' .. errno)
		return false
	end
	-- Close the connection (and free resources) when done
	connection:onidle(connection.close)
	req['connection'] = connection

	return req
end

local function connection_init(time)
	local http_util = require('http.util')
	local ssl_ctx = require('openssl.ssl.context')
	local headers = require('http.headers').new()
	local request = {}

	headers:append(':method', 'GET')
	headers:upsert(':authority', http_util.to_authority(host, port, 'https'))
	headers:upsert(':path', '/dns-query')
	headers:upsert(':scheme', 'https')
	headers:upsert('user-agent', 'doh2.test.lua')
	headers:upsert('content-type', 'application/dns-message')
	request['headers'] = headers;

	local ctx = ssl_ctx.new()
	ctx:setVerify(ssl_ctx.VERIFY_NONE)
	request['ctx'] = ctx;
	request['timeout'] = time

	request = connection_connect(request)

	request['stream1'], err, errno = request['connection']:new_stream()
	if request['stream1'] == nil then
		return nil, err, errno
	end
	request['stream2'], err, errno = request['connection']:new_stream()
	if request['stream2'] == nil then
		return nil, err, errno
	end

	return request
end

local function set_headers_from_body(headers, body)
	local length

	if type(body) == "string" then
		length = #body
	end
	if length then
		headers:upsert("content-length", string.format("%d", #body))
	end
	if not length or length > 1024 then
		headers:append("expect", "100-continue")
	end

	return headers
end

local function send_data(req, stream_name, method, body)
	local pass, err, errno
	local new_headers = set_headers_from_body(req['headers'], body)
	local stream = req[stream_name]

	new_headers:upsert(':method', method)
	do -- Write outgoing headers
		pass, err, errno = stream:write_headers(new_headers, body == nil, req['deadline'] and req['deadline']-monotime())
		if not pass then
			stream:shutdown()
			return nil, err, errno
		end
	end

	if body then
		pass, err, errno = stream:write_body_from_string(body, req['deadline'] and req['deadline']-monotime())
		if not pass then
			stream:shutdown()
			return nil, err, errno
		end
	end

	return pass, err, errno
end

local function read_data(req, stream)
	local headers
	repeat
		local err, errno
		headers, err, errno = stream:get_headers(req['deadline'] and (req['deadline']-monotime()))
		if headers == nil then
			stream:shutdown()
			if err == nil then
				return nil, ce.strerror(ce.EPIPE), ce.EPIPE
			end
			return nil, err, errno
		end
	until not non_final_status(headers:get(":status"))

	return headers, stream
end

local function send_and_check_ok(req, method, desc)
	local pass, headers, stream, stream_check

	-- main request
	pass = send_data(req, 'stream1', method, req['body'])
	if not pass then
		return nil, nil
	end

	headers, stream, errno = read_data(req, req['stream1'])
	if errno then
		local errmsg = stream
		nok(errmsg, desc .. ': ' .. errmsg)
		return nil, nil
	end
	same(tonumber(headers:get(':status')), 200, desc .. ': status 200')
	same(headers:get('content-type'), 'application/dns-message', desc .. ': content-type')
	local answ_headers = headers

	-- test request - noerror.test. A
	req['headers']:upsert('content-type', 'application/dns-message')
	if method == 'GET' then
		req.headers:upsert(':path', '/dns-query?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
	end
	pass = send_data(req, 'stream2', method, method == 'POST' and basexx.from_base64(
		'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB') or nil) -- noerror.test. A
	if not pass then
		return nil, nil
	end

	headers, stream_check, errno = read_data(req, req['stream2'])
	if errno then
		local errmsg = stream_check
		nok(errmsg, desc .. ': ' .. errmsg)
		return nil, nil
	end
	same(tonumber(headers:get(':status')), 200, desc .. ' (test second stream): status 200')
	same(headers:get('content-type'), 'application/dns-message', desc .. ' (test second stream): content-type')

	local body = assert(stream:get_body_as_string())
	local pkt = parse_pkt(body, desc)
	req['stream1']:shutdown()
	req['stream2']:shutdown()

	return answ_headers, pkt
end

local function send_and_check_err(req, method, exp_status, desc)
	local pass, headers, stream, stream_check

	-- main request
	pass = send_data(req, 'stream1', method, req['body'])
	if not pass then
		return
	end

	headers, stream, errno = read_data(req, req['stream1'])
	if errno then
		local errmsg = stream
		nok(errmsg, desc .. ': ' .. errmsg)
		return
	end
	local status = tonumber(headers:get(':status'))
	same(status, exp_status, desc .. ': get ' .. status)

	-- test request
	req['headers']:upsert('content-type', 'application/dns-message')
	if method ~= 'GET' and method ~= 'POST' then
		method = 'GET'
	end
	if method == 'GET' then
		req.headers:upsert(':path', '/dns-query?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
	end
	pass  = send_data(req, 'stream2', method, method == 'POST' and basexx.from_base64(
		'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB') or nil) -- noerror.test. A
	if not pass then
		return
	end
	headers, stream_check, errno = read_data(req, req['stream2'])
	if errno then
		local errmsg = stream_check
		nok(errmsg, desc .. ': ' .. errmsg)
		return
	end
	same(tonumber(headers:get(':status')), 200, desc .. ': second stream: status 200 (exp. 200)')
	same(headers:get('content-type'), 'application/dns-message', desc .. ': second stream: content-type')
	req['stream1']:shutdown()
	req['stream2']:shutdown()
end


if not bound then
	-- skipping doh2 tests (failure to bind may be caused by missing support during build)
	os.exit(77)
else
	policy.add(policy.suffix(policy.DROP, policy.todnames({'servfail.test.'})))
	policy.add(policy.suffix(policy.DENY, policy.todnames({'nxdomain.test.'})))
	policy.add(policy.suffix(gen_varying_ttls, policy.todnames({'noerror.test.'})))


	-- test a valid DNS query using POST
	local function test_post_servfail()
		local desc = 'valid POST query which ends with SERVFAIL'
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- servfail.test. A
			'FZUBAAABAAAAAAAACHNlcnZmYWlsBHRlc3QAAAEAAQ=='))
		local headers, pkt = send_and_check_ok(req, 'POST', desc)
		if not (headers and pkt) then
			return
		end
		-- uncacheable
		same(headers:get('cache-control'), 'max-age=0', desc .. ': TTL 0')
		same(pkt:rcode(), kres.rcode.SERVFAIL, desc .. ': rcode matches')
	end

	local function test_post_noerror()
		local desc = 'valid POST query which ends with NOERROR'
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- noerror.test. A
			'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB'))
		local headers, pkt = send_and_check_ok(req, 'POST', desc)
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
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- nxdomain.test. A
			'viABAAABAAAAAAAACG54ZG9tYWluBHRlc3QAAAEAAQ=='))
		local headers, pkt = send_and_check_ok(req, 'POST', desc)
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
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- huge.test. URI, no EDNS
			'HHwBAAABAAAAAAAABGh1Z2UEdGVzdAABAAAB'))
		local _, pkt = send_and_check_ok(req, 'POST', desc)
		same(pkt:rcode(), kres.rcode.NOERROR, desc .. ': rcode NOERROR')
		same(pkt:tc(), false, desc .. ': no TC bit')
		same(pkt:ancount(), 2, desc .. ': ANSWER contains both RRs')
	end

	-- test an invalid DNS query using POST
	local function test_post_short_input()
		local req = connection_init(timeout)
		request_set_body(req, string.rep('0', 11))  -- 11 bytes < DNS msg header
		send_and_check_err(req, 'POST', 400, 'too short POST finishes with 400')
	end

	local function test_post_unsupp_type()
		local req = connection_init(timeout)
		req['headers']:upsert('content-type', 'application/dns+json')
		request_set_body(req, string.rep('\0', 12))  -- valid message
		send_and_check_err(req, 'POST', 415, 'unsupported request content type finishes with 415')
	end

	local function test_get_right_endpoints()
		local desc = 'GET query with "doh" endpoint'
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_ok(req, 'GET', desc)

		desc = 'GET query with "dns-query" endpoint'
		req = connection_init(timeout)
		req['headers']:upsert(':path', '/dns-query?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_ok(req, 'GET', desc)
	end

	-- test a valid DNS query using GET
	local function test_get_servfail()
		local desc = 'valid GET query which ends with SERVFAIL'
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns='  -- servfail.test. A
			.. 'FZUBAAABAAAAAAAACHNlcnZmYWlsBHRlc3QAAAEAAQ')
		local headers, pkt = send_and_check_ok(req, 'GET', desc)
		if not (headers and pkt) then
			return
		end
		-- uncacheable
		same(headers:get('cache-control'), 'max-age=0', desc .. ': TTL 0')
		same(pkt:rcode(), kres.rcode.SERVFAIL, desc .. ': rcode matches')
	end

	local function test_get_noerror()
		local desc = 'valid GET query which ends with NOERROR'
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns='  -- noerror.test. A
			.. 'vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		local headers, pkt = send_and_check_ok(req, 'GET', desc)
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

	local function test_get_nxdomain()
		local desc = 'valid GET query which ends with NXDOMAIN'
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns='  -- nxdomain.test. A
			.. 'viABAAABAAAAAAAACG54ZG9tYWluBHRlc3QAAAEAAQ')
		local headers, pkt = send_and_check_ok(req, 'GET', desc)
		if not (headers and pkt) then
			return
		end
		same(headers:get('cache-control'), 'max-age=10800', desc .. ': TTL 10800')
		same(pkt:rcode(), kres.rcode.NXDOMAIN, desc .. ': rcode matches')
		same(pkt:nscount(), 1, desc .. ': AUTHORITY is present')
	end

	local function test_get_other_params_before_dns()
		local desc = 'GET query with other parameters before dns is valid'
		local req = connection_init(timeout)
		req['headers']:upsert(':path',
			'/doh?other=something&another=something&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_ok(req, 'GET', desc)
	end

	local function test_get_other_params_after_dns()
		local desc = 'GET query with other parameters after dns is valid'
		local req = connection_init(timeout)
		req['headers']:upsert(':path',
			'/doh?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB&other=something&another=something')
		send_and_check_ok(req, 'GET', desc)
	end

	local function test_get_other_params()
		local desc = 'GET query with other parameters than dns on both sides is valid'
		local req = connection_init(timeout)
		req.headers:upsert(':path',
			'/doh?other=something&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB&another=something')
		send_and_check_ok(req, 'GET', desc)
	end

	-- test an invalid DNS query using GET
	local function test_get_wrong_endpoints()
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/bad?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_err(req, 'GET', 400, 'wrong "bad" endpoint finishes with 400')

		req = connection_init(timeout)
		req['headers']:upsert(':path', '/dns?dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_err(req, 'GET', 400, 'wrong "dns" endpoint finishes with 400')
	end

	local function test_get_no_dns_param()
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?notdns=' .. basexx.to_url64(string.rep('\0', 1024)))
		send_and_check_err(req, 'GET', 400, 'GET without dns parameter finishes with 400')
	end

	local function test_get_unparseable()
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh??dns=' .. basexx.to_url64(string.rep('\0', 1024)))
		send_and_check_err(req, 'GET', 400, 'unparseable GET finishes with 400')
	end

	local function test_get_invalid_b64()
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns=thisisnotb64')
		send_and_check_err(req, 'GET', 400, 'GET with invalid base64 finishes with 400')
	end

	local function test_get_invalid_chars()
		local req = connection_init(timeout)
		req['headers']:upsert(':path', '/doh?dns=' .. basexx.to_url64(string.rep('\0', 200)) .. '@#$%?!')
		send_and_check_err(req, 'GET', 400, 'GET with invalid characters in b64 finishes with 400')
	end

	local function test_get_two_ampersands()
		local req = connection_init(timeout)
		req['headers']:upsert(':path',
			'/doh?other=something&&dns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_err(req, 'GET', 400, 'GET with two ampersands finishes with 400')

		req = connection_init(timeout)
		req['headers']:upsert(':path',
			'/doh?other=something&&nodns=vMEBAAABAAAAAAAAB25vZXJyb3IEdGVzdAAAAQAB')
		send_and_check_err(req, 'GET', 400, 'GET with two ampersands finishes with 400')
	end

	local function test_unsupp_method()
		local req = connection_init(timeout)
		req['headers']:upsert(':method', 'PUT')
		send_and_check_err(req, 'PUT', 405, 'unsupported method finishes with 405')
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
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- dstaddr.test. A
			'FnkBAAABAAAAAAAAB2RzdGFkZHIEdGVzdAAAAQAB'))
		send_and_check_ok(req, 'POST', desc)
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
		local req = connection_init(timeout)
		request_set_body(req, basexx.from_base64(  -- srcaddr.test.knot-resolver.cz TXT
			'QNQBAAABAAAAAAAAB3NyY2FkZHIEdGVzdA1rbm90LXJlc29sdmVyAmN6AAAQAAE'))
		local _, pkt = send_and_check_ok(req, 'POST', desc)
		same(pkt:rcode(), kres.rcode.REFUSED, desc .. ': view module caught it')

		modules.unload('view')
	end

	-- plan tests
	local tests = {
		test_post_servfail,
		test_post_noerror,
		test_post_nxdomain,
		test_huge_answer,
		test_post_short_input,
		test_post_unsupp_type,
		test_get_right_endpoints,
		test_get_servfail,
		test_get_noerror,
		test_get_nxdomain,
		test_get_other_params_before_dns,
		test_get_other_params_after_dns,
		test_get_other_params,
		test_get_wrong_endpoints,
		test_get_no_dns_param,
		test_get_unparseable,
		test_get_invalid_b64,
		test_get_invalid_chars,
		test_get_two_ampersands,
		test_unsupp_method,
		test_dstaddr,
		test_srcaddr
	}

	return tests
end
