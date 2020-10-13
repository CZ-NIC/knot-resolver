-- SPDX-License-Identifier: GPL-3.0-or-later
-- check prerequisites
local has_http = pcall(require, 'kres_modules.http') and pcall(require, 'http.request')
if not has_http then
	-- skipping daf module test because http its not installed
	os.exit(77)
else
	local path = worker.cwd..'/control/'..worker.pid
	same(true, net.listen(path, nil, {kind = 'control'}),
		'new control sockets were created so map() can work')

	local request = require('http.request')

	modules.load('http')
	modules.load('daf')

	local bound
	for _ = 1,1000 do
		bound, _err = pcall(net.listen, '127.0.0.1', math.random(40000, 49999), { kind = 'webmgmt'})
		if bound then
			break
		end
	end
	assert(bound, 'unable to bind a port for HTTP module (1000 attempts)')

	-- globals for this module
	local _, host, port, baseuri
	local function start_server()
		local server_fd = next(http.servers)
		assert(server_fd)
		local server = http.servers[server_fd].server
		ok(server ~= nil, 'creates server instance')
		_, host, port = server:localname()
		ok(host and port, 'binds to an interface')
		baseuri = string.format('http://%s:%d/daf', host, port)
	end

	-- helper for returning useful values to test on
--	local function http_get(uri)
--		local headers, stream = assert(request.new_from_uri(uri):go())
--		local body = assert(stream:get_body_as_string())
--		return tonumber(headers:get(':status')), body, headers:get('content-type')
--	end

	local function http_req(uri, method, reqbody)
		local req = assert(request.new_from_uri(baseuri .. uri))
		req.headers:upsert(':method', method)
		req:set_body(reqbody)
		local headers, stream = assert(req:go())
		local ansbody = assert(stream:get_body_as_string())
		return tonumber(headers:get(':status')), ansbody, headers:get('content-type')
	end

	local function http_get(uri)
		return http_req(uri, 'GET')
	end

	-- compare two tables, expected value is specified as JSON
	-- comparison relies on table_print which sorts table keys
	local function compare_tables(expectedjson, gotjson, desc)
		same(
			table_print(fromjson(expectedjson)),
			table_print(fromjson(gotjson)),
			desc)
	end

	-- test whether http interface responds and binds
	local function test_daf_api()
		local code, body, mime
		-- rule listing /daf
		code, body, mime = http_get('/')
		same(code, 200, 'rule listing return 200 OK')
		same(body, '{}', 'daf rule list is empty after start')
		same(mime, 'application/json', 'daf rule list has application/json content type')
		-- get non-existing rule
		code, body = http_req('/0', 'GET')
		same(code, 404, 'non-existing rule retrieval returns 404')
		same(body, '"No such rule"', 'explanatory message is present')

		-- delete non-existing rule
		code, body = http_req('/0', 'DELETE')
		same(code, 404, 'non-existing rule deletion returns 404')
		same(body, '"No such rule"', 'explanatory message is present')

		-- bad PATCH
		code = http_req('/0', 'PATCH')
		same(code, 400, 'PATCH detects missing parameters')

		-- bad POST
		code = http_req('/', 'POST')
		same(code, 500, 'POST without parameters is detected')

		-- POST first new rule
		code, body, mime = http_req('/', 'POST', 'src = 192.0.2.0 pass')
		same(code, 200, 'first POST succeeds')
		compare_tables(body,
			'{"count":0,"active":true,"id":0,"info":"src = 192.0.2.0 pass"}',
			'POST returns new rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- GET first rule
		code, body, mime = http_req('/0', 'GET')
		same(code, 200, 'GET for first rule succeeds')
		compare_tables(body,
				'{"count":0,"active":true,"id":0,"info":"src = 192.0.2.0 pass"}',
				'POST returns new rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- POST second new rule
		code, body, mime = http_req('/', 'POST', 'src = 192.0.2.1 pass')
		same(code, 200, 'second POST succeeds')
		compare_tables(body,
				'{"count":0,"active":true,"id":1,"info":"src = 192.0.2.1 pass"}',
				'POST returns new rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- GET second rule
		code, body, mime = http_req('/1', 'GET')
		same(code, 200, 'GET for second rule succeeds')
		compare_tables(body,
				'{"count":0,"active":true,"id":1,"info":"src = 192.0.2.1 pass"}',
				'POST returns new rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- PATCH first rule
		code, body, mime = http_req('/0/active/false', 'PATCH')
		same(code, 200, 'PATCH for first rule succeeds')
		same(body, 'true', 'PATCH returns success in body')
		same(mime, 'application/json', 'PATCH return value has application/json content type')

		-- GET modified first rule
		code, body, mime = http_req('/0', 'GET')
		same(code, 200, 'GET for first rule succeeds')
		compare_tables(body,
				'{"count":0,"active":false,"id":0,"info":"src = 192.0.2.0 pass"}',
				'GET returns modified rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- GET both rules
		code, body, mime = http_req('/', 'GET')
		same(code, 200, 'GET for both rule succeeds')
		compare_tables(body, [[
				[
					{"count":0,"active":false,"info":"src = 192.0.2.0 pass","id":0},
					{"count":0,"active":true,"info":"src = 192.0.2.1 pass","id":1}]
				]],
				'GET returns both rules in JSON including modifications')
		same(mime, 'application/json', 'rule list has application/json content type')

		-- PATCH first rule back to original state
		code, body, mime = http_req('/0/active/true', 'PATCH')
		same(code, 200, 'PATCH for first rule succeeds')
		same(body, 'true', 'PATCH returns success in body')
		same(mime, 'application/json', 'PATCH return value has application/json content type')

		-- GET modified (reversed) first rule
		code, body, mime = http_req('/0', 'GET')
		same(code, 200, 'GET for first rule succeeds')
		compare_tables(body,
				'{"count":0,"active":true,"id":0,"info":"src = 192.0.2.0 pass"}',
				'GET returns modified rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- DELETE first rule
		code, body, mime = http_req('/0', 'DELETE')
		same(code, 200, 'DELETE for first rule succeeds')
		same(body, 'true', 'DELETE returns success in body')
		same(mime, 'application/json', 'DELETE return value has application/json content type')

		-- GET deleted (first) rule
		code, body = http_req('/0', 'GET')
		same(code, 404, 'GET for deleted fails with 404')
		same(body, '"No such rule"', 'failed GET contains explanatory message')

		-- GET second rule
		code, body, mime = http_req('/1', 'GET')
		same(code, 200, 'GET for second rule still succeeds')
		compare_tables(body,
				'{"count":0,"active":true,"id":1,"info":"src = 192.0.2.1 pass"}',
				'POST returns new rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- GET list of all rules
		code, body, mime = http_req('/', 'GET')
		same(code, 200, 'GET returns list with the remaining rule')
		compare_tables(body,
				'[{"count":0,"active":true,"id":1,"info":"src = 192.0.2.1 pass"}]',
				'rule list contains only the remaining rule in JSON')
		same(mime, 'application/json', 'rule has application/json content type')

		-- try to DELETE first rule again
		code, body = http_req('/0', 'DELETE')
		same(code, 404, 'DELETE for already deleted rule fails with 404')
		same(body, '"No such rule"', 'DELETE explains failure')

		-- DELETE second rule
		code, body, mime = http_req('/1', 'DELETE')
		same(code, 200, 'DELETE for second rule succeeds')
		same(body, 'true', 'DELETE returns success in body')
		same(mime, 'application/json', 'DELETE return value has application/json content type')

		-- GET (supposedly empty) list of all rules
		code, body, mime = http_req('/', 'GET')
		same(code, 200, 'GET returns list with the remaining rule')
		compare_tables(body, '[]', 'rule list is now empty JSON list')
		same(mime, 'application/json', 'rule has application/json content type')
	end

	-- plan tests
	local tests = {
		start_server,
		test_daf_api,
	}

	return tests
end
