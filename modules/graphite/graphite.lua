local socket = require('cqueues.socket')

-- Load dependent modules
if not stats then modules.load('stats') end

-- This is leader-only module
if worker.id > 0 then return {} end
local M = {}

local function merge(results)
	local t = {}
	for _, result in ipairs(results) do
		for k, v in pairs(result) do
			t[k] = (t[k] or 0) + v
		end
	end
	return t
end

-- Send the metrics in a table to multiple Graphite consumers
local function publish_table(metrics, prefix, now)
	for key,val in pairs(metrics) do
		local msg = key..' '..val..' '..now..'\n'
		if prefix then
			msg = prefix..'.'..msg
		end
		for i, s in ipairs(M.cli) do
			local ok, err = pcall(s.write, s, msg)
			if not ok then
				local host = M.info[i]
				if host.tcp then
					warn('[graphite] reconnecting: %s@%d reason: %s', host.addr, host.port, err)
					M.cli[i] = socket.connect(host.addr, host.port)
				end
			end
		end
	end
end

-- @function Publish results to the Graphite server(s)
local function publish()
	while M.ev do
		-- Sleep for interval
		worker.sleep(M.interval / sec)
		-- Publish built-in statistics
		if #M.cli > 0 then
			local now = os.time()
			publish_table(merge(worker.map 'cache.stats()'), M.prefix..'.cache', now)
			publish_table(merge(worker.map 'worker.stats()'), M.prefix..'.worker', now)
			publish_table(merge(worker.map 'stats.list()'), M.prefix, now)
		end
	end
end

function M.init()
	M.ev = nil
	M.cli = {}
	M.info = {}
	M.interval = 5 * sec
	M.prefix = 'kresd.' .. hostname()
	M.ev = worker.coroutine(publish)
end

function M.deinit()
	if M.ev then
		event.cancel(M.ev)
		M.ev = nil
	end
end

-- @function Make connection to Graphite server.
function M.add_server(_, host, port, tcp)
	local s, err = socket.connect(host, port, nil, tcp and socket.SOCK_STREAM or socket.SOCK_DGRAM)
	if not s then
		panic('[graphite] cannot connect to server: %s', err)
	end
	table.insert(M.cli, s)
	table.insert(M.info, {addr = host, port = port, tcp = tcp})
	return 0
end

function M.config(conf)
	-- config defaults
	if not conf then return 0 end
	if not conf.port then conf.port = 2003 end
	if conf.tcp == nil then conf.tcp = true end
	if conf.interval then M.interval = conf.interval end
	if conf.prefix then M.prefix = conf.prefix end
	-- connect to host(s)
	if type(conf.host) == 'table' then
		for _, val in pairs(conf.host) do
			M:add_server(val, conf.port, conf.tcp)
		end
	else
		M:add_server(conf.host, conf.port, conf.tcp)
	end
end

return M
