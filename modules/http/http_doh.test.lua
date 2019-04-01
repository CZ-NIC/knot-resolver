local basexx = require('basexx')
local ffi = require('ffi')

function parse_pkt(input)
	local wire = ffi.cast("void *", input)
	local pkt = ffi.C.knot_pkt_new(wire, #input, nil);
	assert(output, 'failed to create new packet')

	local result = ffi.C.knot_pkt_parse(pkt, 0)
	ok(result > 0, 'knot_pkt_parse works on received answer')
	print(pkt)
	return pkt
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

	local server = http.servers[1]
	ok(server ~= nil, 'creates server instance')
	local _, host, port = server:localname()
	ok(host and port, 'binds to an interface')
	local uri_templ = string.format('http://%s:%d/doh', host, port)
	local req_templ = assert(request.new_from_uri(uri_templ))
	req_templ.headers:upsert('content-type', 'application/dns-message')

	-- helper for returning useful values to test on
	local function eval_req(req)
		local headers, stream = req:go()
		same(tonumber(headers:get(':status')), 200, 'status 200')
		same(headers:get('content-type'), 'application/dns-message')
		local body = assert(stream:get_body_as_string())
		-- parse packet!
		local pkt = parse_pkt(body)
		return pkt
	end

	local function check_err(req, exp_status, desc)
		local headers, errmsg, errno = req:go(5)  -- TODO: randomly chosen timeout
		if errno then
			nok(errmsg, desc .. ': ' .. errmsg)
			return
		end
		local got_status = headers:get(':status')
		same(got_status, exp_status, desc)
	end

	-- test whether http interface responds and binds
	local function test_doh_post()
		local code, body, mime

		-- simple static page
		local req = req_templ:clone()
		local headers, stream = req:go()
		code, body, mime = eval_req(req)
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
		req:set_body(string.rep('s', 65536))  -- > DNS msg over UDP
		check_err(req, '413', 'too long POST finishes with 413')
	end

	local function test_get_long_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'GET')
		req.headers:upsert(':path', '/doh?dns=' .. basexx.to_url64(string.rep('s', 65536)))
		check_err(req, '414', 'too long GET finishes with 414')
	end

	local function test_post_unparseable_input()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req:set_body(string.rep('\0', 65535))  -- garbage
		check_err(req, '400', 'unparseable DNS message finishes with 400')
	end

	local function test_post_unsupp_type()
		local req = assert(req_templ:clone())
		req.headers:upsert(':method', 'POST')
		req.headers:upsert('content-type', 'application/dns+json')
		req:set_body(string.rep('\0', 12))  -- valid message
		check_err(req, '415', 'unsupported request content type finishes with 415')
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
		-- test_doh_post,
		test_post_short_input,
		test_post_long_input,
		test_get_long_input,
		test_post_unparseable_input,
		test_post_unsupp_type
	}

	return tests
end
