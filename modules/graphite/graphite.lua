--- @module graphite
local graphite = {}
local socket = require('socket')

-- Create connected UDP socket
local function make_udp(host, port)
	local s, err, status
	if host:find(':') then
		s, err = socket.udp6()
	else
		s, err = socket.udp()
	end
	if not s then
		return nil, err
	end
	status, err = s:setpeername(host, port)
	if not status then
		return nil, err
	end
	return s
end

-- Create connected TCP socket
local function make_tcp(host, port)
	local s, err, status
	if host:find(':') then
		s, err = socket.tcp6()
	else
		s, err = socket.tcp()
	end
	if not s then
		return nil, err
	end
	status, err = s:connect(host, port)
	if not status then
		return s, err
	end
	return s
end

-- Send the metrics in a table to multiple Graphite consumers
local function publish_table(metrics, prefix, now)
	for key,val in pairs(metrics) do
		local msg = key..' '..val..' '..now..'\n'
		if prefix then
			msg = prefix..'.'..msg
		end
		for i in ipairs(graphite.cli) do
			local ok, err = graphite.cli[i]:send(msg)
			if not ok then
				-- Best-effort reconnect once per two tries
				local tcp = graphite.cli[i]['connect'] ~= nil
				local host = graphite.info[i]
				if tcp and host.seen + 2 * graphite.interval / 1000 <= now then
					print(string.format('[graphite] reconnecting: %s#%d reason: %s',
						  host.addr, host.port, err))
					graphite.cli[i] = make_tcp(host.addr, host.port)
					host.seen = now
				end
			end
		end
	end
end

function graphite.init(module)
	graphite.ev = nil
	graphite.cli = {}
	graphite.info = {}
	graphite.interval = 5 * sec
	graphite.prefix = 'kresd.' .. hostname()
	return 0
end

function graphite.deinit(module)
	if graphite.ev then event.cancel(graphite.ev) end
	return 0
end

-- @function Publish results to the Graphite server(s)
function graphite.publish()
	local now = os.time()
	-- Publish built-in statistics
	if not graphite.cli then error("no graphite server configured") end
	publish_table(cache.stats(), graphite.prefix..'.cache', now)
	publish_table(worker.stats(), graphite.prefix..'.worker', now)
	-- Publish extended statistics if available
	if not stats then
		return 0
	end
	local now_metrics = stats.list()
	if type(now_metrics) ~= 'table' then
		return 0 -- No metrics to watch
	end
	publish_table(now_metrics, graphite.prefix, now)
	return 0
end

-- @function Make connection to Graphite server.
function graphite.add_server(graphite, host, port, tcp)
	local s, err = tcp and make_tcp(host, port) or make_udp(host, port)
	if not s then
		error(err)
	end
	table.insert(graphite.cli, s)
	table.insert(graphite.info, {addr = host, port = port, seen = 0})
	return 0
end

function graphite.config(conf)
	-- config defaults
	if not conf then return 0 end
	if not conf.port then conf.port = 2003 end
	if conf.interval then graphite.interval = conf.interval end
	if conf.prefix then graphite.prefix = conf.prefix end
	-- connect to host(s)
	if type(conf.host) == 'table' then
		for key, val in pairs(conf.host) do
			graphite:add_server(val, conf.port, conf.tcp)
		end
	else
		graphite:add_server(conf.host, conf.port, conf.tcp)
	end
	-- start publishing stats
	if graphite.ev then event.cancel(graphite.ev) end
	graphite.ev = event.recurrent(graphite.interval, graphite.publish)
	return 0
end

return graphite
