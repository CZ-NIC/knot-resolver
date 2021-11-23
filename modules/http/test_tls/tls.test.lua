-- SPDX-License-Identifier: GPL-3.0-or-later
-- check prerequisites
local has_http = pcall(require, 'kres_modules.http') and pcall(require, 'http.request')
if not has_http then
	-- skipping http module test because its not installed
	os.exit(77)
else
	local request = require('http.request')
	local openssl_ctx = require('openssl.ssl.context')

	local function setup_module(desc, config)
		if http then
			modules.unload('http')
		end
		modules.load('http')
		same(http.config(config), nil, desc .. ' can be configured')

		local bound
		for _ = 1,1000 do
			bound, _err = pcall(net.listen, '127.0.0.1', math.random(1025,65535), { kind = 'webmgmt' })
			if bound then
				break
			end
		end
		assert(bound, 'unable to bind a port for HTTP module (1000 attempts)')

		local server_fd = next(http.servers)
		assert(server_fd)
		local server = http.servers[server_fd].server
		ok(server ~= nil, 'creates server instance')
		_, host, port = server:localname()
		ok(host and port, 'binds to an interface')
		return host, port
	end

	local function http_get(uri)
		-- disable certificate verification in this test
		local req = request.new_from_uri(uri)
		local idxstart = string.find(uri, 'https://')
		if idxstart == 1 then
			req.ctx = openssl_ctx.new()
			assert(req.ctx, 'OpenSSL cert verification must be disabled')
			req.ctx:setVerify(openssl_ctx.VERIFY_NONE)
		end

		local headers = assert(req:go(16))
		return tonumber(headers:get(':status'))
	end

	-- test whether http interface responds and binds
	local function check_protocol(uri, description, ok_expected)
		if ok_expected then
			local code = http_get(uri)
			same(code, 200, description)
		else
			boom(http_get, {uri}, description)
		end
	end

	local function test_defaults()
		local host, port = setup_module('HTTP module default config', nil)

		local uri = string.format('http://%s:%d', host, port)
		check_protocol(uri, 'HTTP is enabled by default', true)
		uri = string.format('https://%s:%d', host, port)
		check_protocol(uri, 'HTTPS is enabled by default', true)

		modules.unload('http')
		uri = string.format('http://%s:%d', host, port)
		check_protocol(uri, 'HTTP stops working after module unload', false)
		uri = string.format('https://%s:%d', host, port)
		check_protocol(uri, 'HTTPS stops working after module unload', false)

	end

	local function test_http_only()
		local desc = 'HTTP-only config'
		local host, port = setup_module(desc,
			{
				tls = false,
			})

		local uri = string.format('http://%s:%d', host, port)
		check_protocol(uri, 'HTTP works in ' .. desc, true)
		uri = string.format('https://%s:%d', host, port)
		check_protocol(uri, 'HTTPS does not work in ' .. desc, false)
	end

	local function test_https_only()
		local desc = 'HTTPS-only config'
		local host, port = setup_module(desc,
			{
				tls = true,
			})

		local uri = string.format('http://%s:%d', host, port)
		check_protocol(uri, 'HTTP does not work in ' .. desc, false)
		uri = string.format('https://%s:%d', host, port)
		check_protocol(uri, 'HTTPS works in ' .. desc, true)
	end

	local function test_custom_cert()
		desc = 'config with custom certificate'
		local host, port = setup_module(desc, {{
				cert = 'test.crt',
				key = 'test.key'
			}})

		uri = string.format('https://%s:%d', host, port)
		check_protocol(uri, 'HTTPS works for ' .. desc, true)
	end

	local function test_nonexistent_cert()
		desc = 'config with non-existing certificate file'
		boom(http.config, {{
				cert = '/tmp/surely_nonexistent_cert_1532432095',
				key = 'test.key'
			}}, desc)
	end

	local function test_nonexistent_key()
		desc = 'config with non-existing key file'
		boom(http.config, {{
				cert = 'test.crt',
				key = '/tmp/surely_nonexistent_cert_1532432095'
			}}, desc)
	end

	local function test_missing_key_param()
		desc = 'config with missing key= param'
		boom(http.config, {{
				cert = 'test.crt'
			}}, desc)
	end

	local function test_broken_cert()
		desc = 'config with broken file in cert= param'
		boom(http.config, {{
				cert = 'broken.crt',
				key = 'test.key'
			}}, desc)
	end

	local function test_broken_key()
		desc = 'config with broken file in key= param'
		boom(http.config, {{
				cert = 'test.crt',
				key = 'broken.key'
			}}, desc)
	end

	local function test_certificate_chain()
		local desc = 'config with certificate chain (with intermediate CA cert)'
		local host, port = setup_module(desc,
			{
				tls = true,
				cert = 'chain.crt',
				key = 'test.key',
			})
		local uri = string.format('https://%s:%d', host, port)
		local req = request.new_from_uri(uri)
		req.ctx = openssl_ctx.new()

		if not req.ctx.setCertificateChain then
			pass(string.format('SKIP (luaossl <= 20181207) - %s', desc))
		else
			local store = req.ctx:getStore()
			store:add('ca.crt')
			req.ctx:setVerify(openssl_ctx.VERIFY_PEER)

			local headers = assert(req:go(16))
			local code = tonumber(headers:get(':status'))
			same(code, 200, desc)
		end
	end


	-- plan tests
	local tests = {
		test_defaults,
		test_http_only,
		test_https_only,
		test_custom_cert,
		test_nonexistent_cert,
		test_nonexistent_key,
		test_missing_key_param,
		test_broken_cert,
		test_broken_key,
		test_certificate_chain,
	}

	return tests
end
