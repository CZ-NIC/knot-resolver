-- SPDX-License-Identifier: GPL-3.0-or-later

-- This is a module that does the heavy lifting to provide an HTTP/2 enabled
-- server that supports TLS by default and provides endpoint for other modules
-- in order to enable them to export restful APIs and websocket streams.
-- One example is statistics module that can stream live metrics on the website,
-- or publish metrics on request for Prometheus scraper.
local http_server = require('http.server')
local http_headers = require('http.headers')
local http_websocket = require('http.websocket')
local http_util = require "http.util"
local x509, pkey = require('openssl.x509'), require('openssl.pkey')

-- Module declaration
local M = {}

-- Export HTTP service endpoints
M.endpoints = {
	['/'] = {'text/html', 'test'},
}

-- Serve known requests, for methods other than GET
-- the endpoint must be a closure and not a preloaded string
local function serve(endpoints, h, stream)
	local hsend = http_headers.new()
	local path = h:get(':path')
	local entry = endpoints[path]
	if not entry then -- Accept top-level path match
		entry = endpoints[path:match '^/[^/?]*']
	end
	-- Unpack MIME and data
	local data, mime, ttl, err
	if entry then
		mime = entry[1]
		data = entry[2]
		ttl = entry[4]
	end
	-- Get string data out of service endpoint
	if type(data) == 'function' then
		local set_mime, set_ttl
		data, err, set_mime, set_ttl = data(h, stream)
		-- Override default endpoint mime/TTL
		if set_mime then mime = set_mime end
		if set_ttl then ttl = set_ttl end
		-- Handler doesn't provide any data
		if data == false then return end
		if type(data) == 'number' then return tostring(data), err end
	-- Methods other than GET require handler to be closure
	elseif h:get(':method') ~= 'GET' then
		return '501', ''
	end
	if not mime or type(data) ~= 'string' then
		return '404', ''
	else
		-- Serve content type appropriately
		hsend:append(':status', '200')
		hsend:append('content-type', mime)
		hsend:append('content-length', tostring(#data))
		if ttl then
			hsend:append('cache-control', string.format('max-age=%d', ttl))
		end
		assert(stream:write_headers(hsend, false))
		assert(stream:write_chunk(data, true))
	end
end

-- Web server service closure
local function route(endpoints)
	return function (_, stream)
		-- HTTP/2: We're only permitted to send in open/half-closed (remote)
		local connection = stream.connection
		if connection.version >= 2 then
			if stream.state ~= 'open' and stream.state ~= 'half closed (remote)' then
				return
			end
		end
		-- Start reading headers
		local h = assert(stream:get_headers())
		local m = h:get(':method')
		local path = h:get(':path')
		-- Upgrade connection to WebSocket
		local ws = http_websocket.new_from_stream(stream, h)
		if ws then
			assert(ws:accept { protocols = {'json'} })
			-- Continue streaming results to client
			local ep = endpoints[path]
			local cb = ep[3]
			if cb then
				cb(h, ws)
			end
			ws:close()
			return
		else
			local ok, err, reason = http_util.yieldable_pcall(serve, endpoints, h, stream)
			if not ok or err then
				print(string.format('%s err %s %s: %s (%s)', os.date(), m, path, err or '500', reason))
				-- Method is not supported
				local hsend = http_headers.new()
				hsend:append(':status', err or '500')
				if reason then
					assert(stream:write_headers(hsend, false))
					assert(stream:write_chunk(reason, true))
				else
					assert(stream:write_headers(hsend, true))
				end
			else
				print(string.format('%s ok  %s %s', os.date(), m, path))
			end
		end
	end
end

-- @function Prefer HTTP/2 or HTTP/1.1
local function alpnselect(_, protos)
	for _, proto in ipairs(protos) do
		if proto == 'h2' or proto == 'http/1.1' then
			return proto
		end
	end
	return nil
end

-- @function Create TLS context
local function tlscontext(crt, key)
	local http_tls = require('http.tls')
	local ctx = http_tls.new_server_context()
	if ctx.setAlpnSelect then
		ctx:setAlpnSelect(alpnselect)
	end
	assert(ctx:setPrivateKey(key))
	assert(ctx:setCertificate(crt))
	return ctx
end

-- @function Listen on given HTTP(s) host
function M.add_interface(conf)
	local crt, key
	if conf.tls ~= false then
		assert(conf.cert, 'cert missing')
		assert(conf.key, 'private key missing')
		-- Check if a cert file was specified
		-- Read x509 certificate
		local f = io.open(conf.cert, 'r')
		if f then
			crt = assert(x509.new(f:read('*all')))
			f:close()
			-- Continue reading key file
			if crt then
				f = io.open(conf.key, 'r')
				key = assert(pkey.new(f:read('*all')))
				f:close()
			end
		end
		-- Check loaded certificate
		assert(crt and key,
		       string.format('failed to load certificate "%s"', conf.cert))
	end
	-- Compose server handler
	local routes = route(conf.endpoints or M.endpoints)
	-- Check if UNIX socket path is used
	local addr_str
	if not conf.path then
		conf.host = conf.host or 'localhost'
		conf.port = conf.port or 8453
		addr_str = string.format('%s@%d', conf.host, conf.port)
	else
		if conf.host or conf.port then
			error('either "path", or "host" and "port" must be provided')
		end
		addr_str = conf.path
	end
	-- Create TLS context and start listening
	local s, err = http_server.listen {
		-- cq = worker.bg_worker.cq,
		host = conf.host,
		port = conf.port,
		path = conf.path,
		v6only = conf.v6only,
		unlink = conf.unlink,
		reuseaddr = conf.reuseaddr,
		reuseport = conf.reuseport,
		client_timeout = conf.client_timeout or 5,
		ctx = crt and tlscontext(crt, key),
		tls = conf.tls,
		onstream = routes,
		-- Log errors, but do not throw
		onerror = function(myserver, context, op, err, errno) -- luacheck: ignore 212
			local msg = '[http] ' .. op .. ' on ' .. tostring(context) .. ' failed'
			if err then
				msg = msg .. ': ' .. tostring(err)
			end
			print(msg)
		end,
	}
	-- Manually call :listen() so that we are bound before calling :localname()
	if s then
		err = select(2, s:listen())
	end
	assert(not err, string.format('failed to listen on %s: %s', addr_str, err))
	return s
end

-- init
local files = {
	'ok0_badtimes.xml',
	'ok1.xml',
	'ok1_expired1.xml',
	'ok1_notyet1.xml',
	'ok2.xml',
	'err_attr_validfrom_missing.xml',
	'err_attr_validfrom_invalid.xml',
	'err_attr_extra_attr.xml',
	'err_elem_missing.xml',
	'err_elem_extra.xml',
	'err_multi_ta.xml',
	'unsupp_nonroot.xml',
	'unsupp_xml_v11.xml'
}

-- Export static pages specified at command line
for _, name in ipairs(files) do
	local fd = io.open(name)
	assert(fd, string.format('unable to open file "%s"', name))
	M.endpoints['/' .. name] = { 'text/xml', fd:read('*a') }
	fd:close()
end

local server = M.add_interface({
	host = 'localhost',
	port = 8080,
	tls = true,
	cert = 'x509/server.pem',
	key = 'x509/server-key.pem'
	})

server:loop()
