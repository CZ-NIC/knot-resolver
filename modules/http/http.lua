-- This is a module that does the heavy lifting to provide an HTTP/2 enabled
-- server that supports TLS by default and provides endpoint for other modules
-- in order to enable them to export restful APIs and websocket streams.
-- One example is statistics module that can stream live metrics on the website,
-- or publish metrics on request for Prometheus scraper.
local cqueues = require('cqueues')
local server = require('http.server')
local headers = require('http.headers')
local websocket = require('http.websocket')
local x509, pkey = require('openssl.x509'), require('openssl.pkey')
local has_mmdb, mmdb  = pcall(require, 'mmdb')

-- Module declaration
local cq = cqueues.new()
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
	local fp, err = io.open(string.format('%s/%s/%s', moduledir, modname, relpath), 'r')
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
	'rickshaw.min.css',
	'kresd.js',
	'datamaps.world.min.js',
	'topojson.js',
	'jquery.js',
	'rickshaw.min.js',
	'd3.js',
}

-- Serve preloaded root page
local function serve_root()
	local data = pgload('main.tpl')[2]
	data = data
	        :gsub('{{ title }}', 'kresd @ '..hostname())
	        :gsub('{{ host }}', hostname())
	return function (h, stream)
		-- Render snippets
		local rsnippets = {}
		for _,v in pairs(M.snippets) do
			table.insert(rsnippets, string.format('<h2>%s</h2>\n%s', v[1], v[2]))
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
for k, v in pairs(require('prometheus')) do
	M.endpoints[k] = v
end

-- Export HTTP service page snippets
M.snippets = {}

-- Serve known requests, for methods other than GET
-- the endpoint must be a closure and not a preloaded string
local function serve(h, stream)
	local hsend = headers.new()
	local path = h:get(':path')
	local entry = M.endpoints[path]
	-- Unpack MIME and data
	local mime, data, err
	if entry then
		mime, data = unpack(entry)
	end
	-- Get string data out of service endpoint
	if type(data) == 'function' then
		data, err = data(h, stream)
		-- Handler doesn't provide any data
		if data == false then return end
		if type(data) == 'number' then return tostring(data) end
	-- Methods other than GET require handler to be closure
	elseif h:get(':method') ~= 'GET' then
		return '501'
	end
	if type(data) == 'table' then data = tojson(data) end
	if not mime or type(data) ~= 'string' then
		return '404'
	else
		-- Serve content type appropriately
		hsend:append(':status', '200')
		hsend:append('content-type', mime)
		local ttl = entry and entry[4]
		if ttl then
			hsend:append('cache-control', string.format('max-age=%d', ttl))
		end
		assert(stream:write_headers(hsend, false))
		assert(stream:write_chunk(data, true))
	end
end

-- Web server service closure
local function route(endpoints)
	return function (stream)
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
		local ws = websocket.new_from_stream(h, stream)
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
			local ok, err = pcall(serve, h, stream)
			if not ok or err then
				log('[http] %s %s: %s', m, path, err or '500')
				-- Method is not supported
				local hsend = headers.new()
				hsend:append(':status', err or '500')
				assert(stream:write_headers(hsend, true))
			end
		end
		stream:shutdown()
	end
end

-- @function Create self-signed certificate
local function ephemeralcert(host)
	-- Import luaossl directly
	local name = require('openssl.x509.name')
	local altname = require('openssl.x509.altname')
	-- Create self-signed certificate
	host = host or hostname()
	local crt = x509.new()
	local now = os.time()
	crt:setSerial(now)
	local dn = name.new()
	dn:add("CN", host)
	crt:setSubject(dn)
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
			panic('failed to load certificate "%s" - %s', crtfile, err or 'error')
		end
	end
	-- Create TLS context and start listening
	local s, err = server.listen {
		host = host,
		port = port,
		client_timeout = 5,
		ctx = crt and tlscontext(crt, key),
	}
	if not s then
		panic('failed to listen on %s#%d: %s', host, port, err)
	end
	-- Compose server handler
	local routes = route(endpoints)
	cq:wrap(function ()
		assert(s:run(routes))
		s:close()
	end)
	table.insert(M.servers, s)
	-- Create certificate renewal timer if ephemeral
	if crt and ephemeral then
		local _, expiry = crt:getLifetime()
		expiry = math.max(0, expiry - (os.time() - 3 * 24 * 3600))
		event.after(expiry, function (ev)
			log('[http] refreshed ephemeral certificate')
			crt, key = updatecert(crtfile, keyfile)
			s.ctx = tlscontext(crt, key)
		end)
	end
end

-- @function Cleanup module
function M.deinit()
	if M.ev then event.cancel(M.ev) end
	M.servers = {}
end

-- @function Configure module
function M.config(conf)
		conf = conf or {}
		assert(type(conf) == 'table', 'config { host = "...", port = 443, cert = "...", key = "..." }')
		-- Configure web interface for resolver
		if not conf.port then conf.port = 8053 end
		if not conf.host then conf.host = 'localhost' end
		if conf.geoip and has_mmdb then M.geoip = mmdb.open(conf.geoip) end
		M.interface(conf.host, conf.port, M.endpoints, conf.cert, conf.key)
		-- TODO: configure DNS/HTTP(s) interface
		if M.ev then return end
		-- Schedule both I/O activity notification and timeouts
		local poll_step
		poll_step = function ()
			local ok, err, _, co = cq:step(0)
			if not ok then warn('[http] error: %s %s', err, debug.traceback(co)) end
			-- Reschedule timeout or create new one
			local timeout = cq:timeout()
			if timeout then
				-- Throttle web requests
				if timeout == 0 then timeout = 0.001 end
				-- Convert from seconds to duration
				timeout = timeout * sec
				if not M.timeout then
					M.timeout = event.after(timeout, poll_step)
				else
					event.reschedule(M.timeout, timeout)
				end
			else -- Cancel running timeout when there is no next deadline
				if M.timeout then
					event.cancel(M.timeout)
					M.timeout = nil
				end
			end
		end
		M.ev = event.socket(cq:pollfd(), poll_step)
end

return M
