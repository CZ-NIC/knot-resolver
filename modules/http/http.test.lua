-- SPDX-License-Identifier: GPL-3.0-or-later
-- check prerequisites
local has_http = pcall(require, 'kres_modules.http') and pcall(require, 'http.request')
if not has_http then
	-- skipping http module test because its not installed
	os.exit(77)
else
	local path = worker.cwd..'/control/'..worker.pid
	same(true, net.listen(path, nil, {kind = 'control'}),
		'new control sockets were created so map() can work')

	local request = require('http.request')

	modules.load('http')
	local endpoints = http.configs._builtin.webmgmt.endpoints

	-- custom endpoints
	endpoints['/test'] = {'text/custom', function () return 'hello' end}

	-- setup HTTP module with an additional endpoint
	http.config({
		tls = false,
		endpoints = endpoints,
	}, 'webtest')

	local bound
	for _ = 1,1000 do
		bound, _err = pcall(net.listen, '127.0.0.1', math.random(20000, 29999), { kind = 'webtest'})
		if bound then
			break
		end
	end
	assert(bound, 'unable to bind a port for HTTP module (1000 attempts)')

	-- globals for this module
	local _, host, port
	local function start_server()
		local server_fd = next(http.servers)
		assert(server_fd)
		local server = http.servers[server_fd].server
		ok(server ~= nil, 'creates server instance')
		_, host, port = server:localname()
		ok(host and port, 'binds to an interface')
	end

	-- helper for returning useful values to test on
	local function http_get(uri)
		local headers, stream = assert(request.new_from_uri(uri .. '/'):go())
		local body = assert(stream:get_body_as_string())
		return tonumber(headers:get(':status')), body, headers:get('content-type')
	end

	-- test whether http interface responds and binds
	local function test_builtin_pages()
		local code, body, mime
		local uri = string.format('http://%s:%d', host, port)
		-- simple static page
		code, body, mime = http_get(uri .. '/')
		same(code, 200, 'static page return 200 OK')
		ok(#body > 0, 'static page has non-empty body')
		same(mime, 'text/html', 'static page has text/html content type')
		-- custom endpoint
		code, body, mime = http_get(uri .. '/test')
		same(code, 200, 'custom page return 200 OK')
		same(body, 'hello', 'custom page has non-empty body')
		same(mime, 'text/custom', 'custom page has custom content type')
		-- non-existent page
		code = http_get(uri .. '/badpage')
		same(code, 404, 'non-existent page returns 404')
		-- /stats endpoint serves metrics
		code, body, mime = http_get(uri .. '/stats')
		same(code, 200, '/stats page return 200 OK')
		ok(#body > 0, '/stats page has non-empty body')
		same(mime, 'application/json', '/stats page has correct content type')
		-- /metrics serves metrics
		code, body, mime = http_get(uri .. '/metrics')
		same(code, 200, '/metrics page return 200 OK')
		ok(#body > 0, '/metrics page has non-empty body')
		same(mime, 'text/plain; version=0.0.4', '/metrics page has correct content type')
		-- /metrics serves frequent
		code, body, mime = http_get(uri .. '/frequent')
		same(code, 200, '/frequent page return 200 OK')
		ok(#body > 0, '/frequent page has non-empty body')
		same(mime, 'application/json', '/frequent page has correct content type')
		-- /metrics serves bogus
		code, body, mime = http_get(uri .. '/bogus')
		same(code, 200, '/bogus page return 200 OK')
		ok(#body > 0, '/bogus page has non-empty body')
		same(mime, 'application/json', '/bogus page has correct content type')
		-- /trace serves trace log for requests
		code, body, mime = http_get(uri .. '/trace/localhost/A')
		same(code, 200, '/trace page return 200 OK')
		ok(#body > 0, '/trace page has non-empty body')
		same(mime, 'text/plain', '/trace page has correct content type')
		-- /trace checks variables
		code = http_get(uri .. '/trace/localhost/BADTYPE')
		same(code, 400, '/trace checks type')
		code = http_get(uri .. '/trace/')
		same(code, 400, '/trace requires name')
	end

	-- AF_UNIX tests (very basic ATM)
	local function test_unix_socket()
		local s_path = os.tmpname()
		os.remove(s_path) -- on POSIX .tmpname() (usually) creates a file :-/
		ok(net.listen(s_path, nil, { kind = 'webmgmt' }),  'AF_UNIX net.listen() on ' .. s_path)
		-- Unfortunately we can't use standard functions for fetching http://
		local socket = require("cqueues.socket")
		local sock = socket.connect({ path = s_path })
		local connection = require('http.h2_connection')
		local conn = connection.new(sock, 'client')
		local _, err = conn:connect()
		os.remove(s_path) -- don't leave garbage around, hopefully not even on errors
		same(err, nil, 'AF_UNIX connect(): ' .. (err or 'OK'))
		same(conn:ping(), true, 'AF_UNIX http ping')
		-- here we might do `conn:new_stream()` and some real queries
		same(conn:close(), true, 'AF_UNIX close')
	end

	-- plan tests
	local tests = {
		start_server,
		test_builtin_pages,
		test_unix_socket,
	}

	return tests
end
