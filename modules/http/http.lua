local cqueues = require('cqueues')
local ce = require('cqueues.errno')
local server = require('http.server')
local headers = require('http.headers')
local websocket = require('http.websocket')
local kres = require('kres')

-- Module declaration
local cq = cqueues.new()
local M = {
	servers = {},
}

-- Load dependent modules
if not stats then modules.load('stats') end
local function stream_stats(h, ws)
	local ok, err = true, nil
	while ok do
		-- Receive PINGs
		ok, err = ws:receive()
		if not ok then
			ws.socket:clearerr()
		end
		-- Stream 
		ok, err = ws:send(tojson(stats.list()))
	end
	ws:close()
end

-- Preload static contents, nothing on runtime will touch the disk
local function pgload(relpath)
	local fp, err = io.open(moduledir..'/http/'..relpath, 'r')
	if not fp then error(err) end
	local data = fp:read('*all')
	fp:close()
	return data
end
local pages = {
	root = pgload('main.tpl'):gsub('{{.Title}}', 'kresd @ '..hostname()),
	rootjs = pgload('tinyweb.js'),
	datamaps = pgload('datamaps.world.min.js'),
	topojson = pgload('topojson.js'),
	jquery = pgload('jquery.js'),
	epochcss = pgload('epoch.css'),
	epoch = pgload('epoch.js'),
	favicon = pgload('favicon.ico'),
	d3 = pgload('d3.js'),
}

-- Export HTTP service endpoints
M.endpoints = {
	['/']                      = {'text/html', pages.root},
	['/tinyweb.js']            = {'application/json', pages.rootjs},
	['/datamaps.world.min.js'] = {'application/json', pages.datamaps},
	['/topojson.js']           = {'application/json', pages.topojson},
	['/jquery.js']             = {'application/json', pages.jquery},
	['/epoch.js']              = {'application/json', pages.epoch},
	['/epoch.css']             = {'text/css', pages.epochcss},
	['/favicon.ico']           = {'text/html', pages.favicon},
	['/d3.js']                 = {'text/html', pages.d3},
	['/stats']                 = {'application/json', stats.list, stream_stats},
	['/feed']                  = {'application/json', stats.frequent},

}

-- Serve GET requests, we only support a fixed
-- number of endpoints that are actually preloaded
-- in memory or constructed on request
local function serve_get(h, stream)
	local hsend = headers.new()
	local path = h:get(':path')
	local ctype, data = M.endpoints[path]
	-- Unpack ctype
	if ctype then
		ctype, data = unpack(ctype)
	end
	-- Get string data out of service endpoint
	if type(data) == 'function' then data = data(h) end
	if type(data) == 'table' then data = tojson(data) end
	if not ctype or type(data) ~= 'string' then
		hsend:append(':status', '404')
		hsend:append('connection', 'close')
		assert(stream:write_headers(hsend, true))
	else
		-- Serve content type appropriately
		hsend:append(':status', '200')
		hsend:append('content/type', ctype)
		hsend:append('connection', 'close')
		assert(stream:write_headers(hsend, false))
		assert(stream:write_chunk(data, true))
	end
end

-- Web server service closure
function M.route(endpoints)
	return function (stream)
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
			return
		-- Handle HTTP method appropriately
		elseif m == 'GET' then
			serve_get(h, stream)
		else
			-- Method is not supported
			local hsend = headers.new()
			hsend:append(':status', '500')
			hsend:append('connection', 'close')
			assert(stream:write_headers(hsend, true))
		end
		stream:shutdown()
		stream.connection:shutdown()
	end
end

-- @function Listen on given HTTP(s) host
function M.listen(m, host, port, cb, cert)
	local s, err = server.listen {
		host = host,
		port = port,
	}
	if not s then
		error(string.format('failed to listen on %s#%d: %s', host, port, err))
	end
	-- Compose server handler
	cq:wrap(function ()
		assert(s:run(cb))
		s:close()
	end)
	table.insert(M.servers, s)
end

-- @function 

-- @function Cleanup module
function M.deinit()
	if M.ev then event.cancel(M.ev) end
	M.servers = {}
end

-- @function Configure module
function M.config(conf)
		assert(type(conf) == 'table', 'config { host = "...", port = 443, cert = "..." }')
		-- Configure web interface for resolver
		if not conf.port then conf.port = conf.cert and 80 or 443 end
		if not conf.host then conf.host = 'localhost' end 
		M:listen(conf.host, conf.port, M.route(M.endpoints))
		-- TODO: configure DNS/HTTP(s) interface
		-- M:listen(conf.dns.host, conf.dns/port, serve_web)
		if M.ev then return end
		M.ev = event.socket(cq:pollfd(), function (ev, status, events)
			local ok, err, _, co = cq:step(0)
			if not ok then print('[http] '..err, debug.traceback(co)) end
		end)
end

return M
