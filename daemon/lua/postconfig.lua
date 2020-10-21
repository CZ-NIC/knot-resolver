-- SPDX-License-Identifier: GPL-3.0-or-later

local ffi = require('ffi')
local C = ffi.C

local function count_sockets()
	local dns_socks = 0
	local control_socks = 0
	for _, socket in ipairs(net.list()) do
		if socket.kind == 'control' then
			control_socks = control_socks + 1
		elseif (socket.kind == 'dns' or
			socket.kind == 'xdp' or
			socket.kind == 'tls' or
			socket.kind == 'doh' or
			socket.kind == 'doh2') then
			dns_socks = dns_socks + 1
		end
	end
	return dns_socks, control_socks
end

local n_dns_socks, n_control_socks = count_sockets()

-- Check and set control sockets path
worker.control_path = worker.control_path or (worker.cwd .. '/control/')

-- Bind to control socket by default
if n_control_socks == 0 and not env.KRESD_NO_LISTEN then
	local path = worker.control_path..worker.pid
	local ok, err = pcall(net.listen, path, nil, { kind = 'control' })
	if not ok then
		warn('bind to '..path..' failed '..err)
	end
end

-- Listen on localhost
if n_dns_socks == 0 and not env.KRESD_NO_LISTEN then
	local ok, err = pcall(net.listen, '127.0.0.1')
	if not ok then
		error('bind to 127.0.0.1@53 '..err)
	end
	-- Binding to other ifaces may fail
	ok, err = pcall(net.listen, '127.0.0.1', 853)
	if not ok and verbose() then
		log('bind to 127.0.0.1@853 '..err)
	end
	ok, err = pcall(net.listen, '::1')
	if not ok and verbose() then
		log('bind to ::1@53 '..err)
	end
	ok, err = pcall(net.listen, '::1', 853)
	if not ok and verbose() then
		log('bind to ::1@853 '..err)
	end
	-- Exit when kresd isn't listening on any interfaces
	n_dns_socks, _ = count_sockets()
	if n_dns_socks == 0 then
		panic('not listening on any interface, exiting...')
	end
end
-- Open cache if not set/disabled
if not cache.current_size then
	cache.size = 100 * MB
end

-- If no addresses for root servers are set, load them from the default file
if C.kr_zonecut_is_empty(kres.context().root_hints) then
	_hint_root_file()
end
