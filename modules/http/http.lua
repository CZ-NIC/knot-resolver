-- Load dependent modules
if not stats then modules.load('stats') end

-- This is leader-only module
if worker.id > 0 then return {} end

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
local has_mmdb, mmdb  = pcall(require, 'mmdb')

-- Module declaration
local M = {
	servers = {},
}

-- Map extensions to MIME type
local mime_types = {
	js = 'application/javascript',
	css = 'text/css',
	tpl = 'text/html',
	ico = 'image/x-icon'
}

-- Preload static contents, nothing on runtime will touch the disk
local function pgload(relpath, modname)
	if not modname then modname = 'http' end
	local mdir = moduledir()
	local fp, err = io.open(string.format('%s/%s/%s', mdir, modname, relpath), 'r')
	if not fp then
		fp, err = io.open(string.format('%s/%s/static/%s', mdir, modname, relpath), 'r')
	end
	if not fp then error(err) end
	local data = fp:read('*all')
	fp:close()
	-- Guess content type
	local ext = relpath:match('[^\\.]+$')
	return {mime_types[ext] or 'text', data, nil, 86400}
end
M.page = pgload

-- Preloaded static assets
local pages = {
	'favicon.ico',
	'kresd.js',
	'kresd.css',
	'jquery.js',
	'd3.js',
	'topojson.js',
	'datamaps.world.min.js',
	'dygraph-combined.js',
	'selectize.min.js',
	'selectize.min.css',
	'selectize.bootstrap3.min.css',
	'bootstrap.min.js',
	'bootstrap.min.css',
	'bootstrap-theme.min.css',
	'glyphicons-halflings-regular.woff2',
}

-- Serve preloaded root page
local function serve_root()
	local data = pgload('main.tpl')[2]
	data = data
	        :gsub('{{ title }}', M.title or ('kresd @ ' .. hostname()))
	        :gsub('{{ host }}', hostname())
	return function (_, stream)
		-- Render snippets
		local rsnippets = {}
		for _,v in pairs(M.snippets) do
			local sid = string.lower(string.gsub(v[1], ' ', '-'))
			table.insert(rsnippets, string.format('<section id="%s"><h2>%s</h2>\n%s</section>', sid, v[1], v[2]))
		end
		-- Return index page
		return data
		        :gsub('{{ secure }}', stream:checktls() and 'true' or 'false')
		        :gsub('{{ snippets }}', table.concat(rsnippets, '\n'))
	end
end

-- Export HTTP service endpoints
M.endpoints = {
	['/'] = {'text/html', serve_root()},
}

-- Export static pages
for _, pg in ipairs(pages) do
	M.endpoints['/'..pg] = pgload(pg)
end

-- Export built-in prometheus interface
local prometheus = require('prometheus')
for k, v in pairs(prometheus.endpoints) do
	M.endpoints[k] = v
end
M.prometheus = prometheus

-- Export built-in trace interface
local http_trace = require('http_trace')
for k, v in pairs(http_trace.endpoints) do
	M.endpoints[k] = v
end
M.trace = http_trace

-- Export HTTP service page snippets
M.snippets = {}

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
	if type(data) == 'table' then data = tojson(data) end
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
				if err ~= '404' and verbose() then
					log('[http] %s %s: %s (%s)', m, path, err or '500', reason)
				end
				-- Method is not supported
				local hsend = http_headers.new()
				hsend:append(':status', err or '500')
				if reason then
					assert(stream:write_headers(hsend, false))
					assert(stream:write_chunk(reason, true))
				else
					assert(stream:write_headers(hsend, true))
				end
			end
		end
	end
end

-- @function Create self-signed certificate
local function ephemeralcert(host)
	-- Import luaossl directly
	local name = require('openssl.x509.name')
	local altname = require('openssl.x509.altname')
	local openssl_bignum = require('openssl.bignum')
	local openssl_rand = require('openssl.rand')
	-- Create self-signed certificate
	host = host or hostname()
	local crt = x509.new()
	local now = os.time()
	crt:setVersion(3)
	-- serial needs to be unique or browsers will show uninformative error messages
	crt:setSerial(openssl_bignum.fromBinary(openssl_rand.bytes(16)))
	-- use the host we're listening on as canonical name
	local dn = name.new()
	dn:add("CN", host)
	crt:setSubject(dn)
	crt:setIssuer(dn) -- should match subject for a self-signed
	local alt = altname.new()
	alt:add("DNS", host)
	crt:setSubjectAlt(alt)
	-- Valid for 90 days
	crt:setLifetime(now, now + 90*60*60*24)
	-- Can't be used as a CA
	crt:setBasicConstraints{CA=false}
	crt:setBasicConstraintsCritical(true)
	-- Create and set key (default: EC/P-256 as a most "interoperable")
	local key = pkey.new {type = 'EC', curve = 'prime256v1'}
	crt:setPublicKey(key)
	crt:sign(key)
	return crt, key
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

-- @function Refresh self-signed certificates
local function updatecert(crtfile, keyfile)
	local f = assert(io.open(crtfile, 'w'), string.format('cannot open "%s" for writing', crtfile))
	local crt, key = ephemeralcert()
	-- Write back to file
	f:write(tostring(crt))
	f:close()
	f = assert(io.open(keyfile, 'w'), string.format('cannot open "%s" for writing', keyfile))
	local pub, priv = key:toPEM('public', 'private')
	assert(f:write(pub..priv))
	f:close()
	return crt, key
end

-- @function Listen on given HTTP(s) host
function M.interface(host, port, endpoints, crtfile, keyfile)
	local crt, key, ephemeral
	if crtfile ~= false then
		-- Check if the cert file exists
		if not crtfile then
			crtfile = 'self.crt'
			keyfile = 'self.key'
			ephemeral = true
		else error('certificate provided, but missing key') end
		-- Read or create self-signed x509 certificate
		local f = io.open(crtfile, 'r')
		if f then
			crt = assert(x509.new(f:read('*all')))
			f:close()
			-- Continue reading key file
			if crt then
				f = io.open(keyfile, 'r')
				key = assert(pkey.new(f:read('*all')))
				f:close()
			end
		elseif ephemeral then
			crt, key = updatecert(crtfile, keyfile)
		end
		-- Check loaded certificate
		if not crt or not key then
			panic('failed to load certificate "%s"', crtfile)
		end
	end
	-- Compose server handler
	local routes = route(endpoints)
	-- Create TLS context and start listening
	local s, err = http_server.listen {
		cq = worker.bg_worker.cq,
		host = host,
		port = port,
		client_timeout = 5,
		ctx = crt and tlscontext(crt, key),
		onstream = routes,
	}
	-- Manually call :listen() so that we are bound before calling :localname()
	if s then
		err = select(2, s:listen())
	end
	if err then
		panic('failed to listen on %s@%d: %s', host, port, err)
	end
	table.insert(M.servers, s)
	-- Create certificate renewal timer if ephemeral
	if crt and ephemeral then
		local _, expiry = crt:getLifetime()
		expiry = math.max(0, expiry - (os.time() - 3 * 24 * 3600))
		event.after(expiry, function ()
			log('[http] refreshed ephemeral certificate')
			crt, key = updatecert(crtfile, keyfile)
			s.ctx = tlscontext(crt, key)
		end)
	end
end

-- @function Init module
function M.init()
	worker.coroutine(prometheus.init)
end

-- @function Cleanup module
function M.deinit()
	for i, server in ipairs(M.servers) do
		server:close()
		M.servers[i] = nil
	end
	prometheus.deinit()
end

-- @function Configure module
function M.config(conf)
	if conf == true then conf = {} end
	assert(type(conf) == 'table', 'config { host = "...", port = 443, cert = "...", key = "..." }')
	-- Configure web interface for resolver
	if not conf.port then conf.port = 8053 end
	if not conf.host then conf.host = 'localhost' end
	if conf.geoip then
		if has_mmdb then
			M.geoip = mmdb.open(conf.geoip)
		else
			error('[http] mmdblua library not found, please remove GeoIP configuration')
		end
	end
	-- Add endpoints to default endpoints
	local endpoints = conf.endpoints or {}
	for k, v in pairs(M.endpoints) do
		endpoints[k] = v
	end
	M.interface(conf.host, conf.port, endpoints, conf.cert, conf.key)
end

return M
