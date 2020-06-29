-- SPDX-License-Identifier: GPL-3.0-or-later
-- Load dependent modules
if not stats then modules.load('stats') end

-- This is leader-only module
if worker.id > 0 then return {} end
local M = {}
local socket = require("cqueues.socket")
local proto_txt = {
	[socket.SOCK_DGRAM] = 'udp',
	[socket.SOCK_STREAM] = 'tcp'
}

local function make_socket(host, port, stype)
	local s, err, status

	s = socket.connect({ host = host, port = port, type = stype })
	s:setmode('bn', 'bn')
	status, err = pcall(s.connect, s)

	if not status then
		log('[graphite] connecting: %s@%d %s reason: %s',
			host, port, proto_txt[stype], err)
		return status, err
	end
	return s
end

-- Create connected UDP socket
local function make_udp(host, port)
	return make_socket(host, port, socket.SOCK_DGRAM)
end

-- Create connected TCP socket
local function make_tcp(host, port)
	return make_socket(host, port, socket.SOCK_STREAM)
end

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
	local s
	for i in ipairs(M.cli) do
		local host = M.info[i]

		if M.cli[i] == -1 then
			if host.tcp then
				s = make_tcp(host.addr, host.port)
			else
				s = make_udp(host.addr, host.port)
			end
			if s then
				M.cli[i] = s
			end
		end

		if M.cli[i] ~= -1 then
			for key,val in pairs(metrics) do
				local msg = key..' '..val..' '..now..'\n'
				if prefix then
					msg = prefix..'.'..msg
				end

				local ok, err = pcall(M.cli[i].write, M.cli[i], msg)
				if not ok then
					local tcp = M.cli[i]['connect'] ~= nil
					if tcp and host.seen + 2 * M.interval / 1000 <= now then
						local sock_type = (host.tcp and socket.SOCK_STREAM)
									or socket.SOCK_DGRAM
						log('[graphite] reconnecting: %s@%d %s reason: %s',
							  host.addr, host.port, proto_txt[sock_type], err)
						s = make_tcp(host.addr, host.port)
						if s then
							M.cli[i] = s
							host.seen = now
						else
							M.cli[i] = -1
							break
						end
					end
				end
			end -- loop metrics
		end
	end -- loop M.cli
end

function M.init()
	M.ev = nil
	M.cli = {}
	M.info = {}
	M.interval = 5 * sec
	M.prefix = 'kresd.' .. hostname()
	return 0
end

function M.deinit()
	if M.ev then event.cancel(M.ev) end
	return 0
end

-- @function Publish results to the Graphite server(s)
function M.publish()
	local now = os.time()
	-- Publish built-in statistics
	if not M.cli then error("no graphite server configured") end
	publish_table(merge(map 'cache.stats()'), M.prefix..'.cache', now)
	publish_table(merge(map 'worker.stats()'), M.prefix..'.worker', now)
	-- Publish extended statistics if available
	publish_table(merge(map 'stats.list()'), M.prefix, now)
	return 0
end

-- @function Make connection to Graphite server.
function M.add_server(_, host, port, tcp)
	local s
	if tcp then
		s = make_tcp(host, port)
	else
		s = make_udp(host, port)
	end
	if not s then
		s = -1
	end
	table.insert(M.cli, s)
	table.insert(M.info, {addr = host, port = port, tcp = tcp, seen = 0})
	return 0
end

function M.config(conf)
	-- config defaults
	if not conf then return 0 end
	if not conf.port then conf.port = 2003 end
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
	-- start publishing stats
	if M.ev then event.cancel(M.ev) end
	M.ev = event.recurrent(M.interval, M.publish)
	return 0
end

return M
