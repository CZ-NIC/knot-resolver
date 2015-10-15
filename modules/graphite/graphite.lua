--- @module graphite
local graphite = {}

function graphite.init(module)
	graphite.socket = require('socket')
	graphite.ev = nil
	graphite.cli = {}
	graphite.prefix = nil
	return 0
end

function graphite.deinit(module)
	if graphite.ev then event.cancel(graphite.ev) end
	return 0
end

-- @function Publish results to the Graphite server(s)
function graphite.publish()
	local now = os.time()
	if not graphite.cli then error("no graphite server configured") end
	local now_metrics = stats.list()
	if type(now_metrics) ~= 'table' then
		return 0 -- No metrics to watch
	end
	local function publish_table(metrics, prefix)
		for key,val in pairs(metrics) do
			local msg = key..' '..val..' '..now..'\n'
			if prefix then
				msg = prefix..'.'..msg
			end
			for i in ipairs(graphite.cli) do
				graphite.cli[i]:send(msg)
			end
		end
	end
	publish_table(now_metrics, graphite.prefix)
	publish_table(cache.stats(), graphite.prefix..'.cache')
	publish_table(worker.stats(), graphite.prefix..'.worker')
	return 0
end

-- @function Make connection to Graphite server.
function graphite.add_server(graphite, host, port)
	local cli, err, status
	if host:find(':') then
		cli, err = graphite.socket.udp6()
	else
		cli, err = graphite.socket.udp()
	end
	if not cli then
		error(err)
	end
	status, err = cli:setpeername(host, port)
	if not status then
		error(err)
	end
	table.insert(graphite.cli, cli)
	return 0
end

function graphite.config(conf)
	-- config defaults
	if not conf then return 0 end
	if not conf.port then conf.port = 2003 end
	if not conf.interval then conf.interval = 5 * sec end
	if conf.prefix then graphite.prefix = conf.prefix end
	-- connect to host(s)
	if type(conf.host) == 'table' then
		for key, val in pairs(conf.host) do
			graphite:add_server(val, conf.port)
		end
	else
		graphite:add_server(conf.host, conf.port)
	end
	-- start publishing stats
	if graphite.ev then event.cancel(graphite.ev) end
	graphite.ev = event.recurrent(conf.interval, graphite.publish)
	return 0
end

return graphite
