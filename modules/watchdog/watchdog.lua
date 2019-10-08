ffi = require('ffi')

ffi.cdef([[
	int sd_watchdog_enabled(int unset_environment, uint64_t *usec);
	int sd_notify(int unset_environment, const char *state);
]])

local watchdog = {}
local private = {}

local function sd_signal_ok()
	ffi.C.sd_notify(0, 'WATCHDOG=1')
end

-- logging
local function add_tracer(logbuf)
	return function (req)
		local function qrylogger(qry, src, msg)
			local req_uid = (qry and qry.request and qry.request.uid) or 0
			local qry_uid = (qry and qry.uid) or 0
			local logline = string.format("[%05u.%02u][%s] %s", req_uid, qry_uid, ffi.string(src), ffi.string(msg))
			table.insert(logbuf, logline)
			if verbose() then  -- without this message would be missing in verbose log
				ffi.C.kr_log_qverbose_impl(qry, src, msg)
			end
		end
		req.trace_log = ffi.cast('trace_log_f', qrylogger)
	end
end

local function check_answer(logbuf)
	return function (pkt, req)
		if pkt:rcode() == kres.rcode.NOERROR or pkt:rcode() == kres.rcode.NXDOMAIN then
			private.ok_callback()
			return
		end
		-- failure! quit immediatelly to allow process supervisor to restart us
		log('[watchdog] watchdog query returned unexpected answer! query verbose log:')
		log(table.concat(logbuf, ''))
		log('[watchdog] problematic answer:\n%s', pkt)
		log('[watchdog] TERMINATING resolver, supervisor should restart it now')
		quit()
	end
end
private.check_answer_callback = check_answer

local function timer()
	local logbuf = {}
	-- fire watchdog query
	if private.qname and private.qtype then
		if verbose() then
			log('[watchdog] starting watchdog query %s %s', private.qname, private.qtype)
		end
		resolve(private.qname,
			private.qtype,
			kres.class.IN,
			{'TRACE'},
			private.check_answer_callback(logbuf),
			add_tracer(logbuf))
	else
		private.ok_callback()
	end
end

function watchdog.config(cfg)
	-- read only
	if not cfg then
		return private
	end

	if cfg.interval then
		local interval = tonumber(cfg.interval)
		if not interval or interval < 1 then
			error('[watchdog] interval must be >= 1 ms')
		end
		private.interval = interval
	end
	if cfg.qname or cfg.qtype then
		private.qname = cfg.qname
		private.qtype = cfg.qtype
	end
	-- restart timers
	watchdog.deinit()
	private.event = event.recurrent(private.interval, timer)
	return private
end

-- automatically enable watchdog if it is configured in systemd
function watchdog.init()
	if private.event then
		error('[watchdog] module is already loaded')
	end
	local timeoutptr = ffi.new('uint64_t[1]')
	local systemd_present, ret = pcall(function() return ffi.C.sd_watchdog_enabled(0, timeoutptr) end)
	if not systemd_present then
		if verbose() then
			log('[watchdog] systemd library not detected')
		end
		return
	end
	private.ok_callback = sd_signal_ok
	if ret < 0 then
		error('[watchdog] %s', ffi.C.strerror(abs(ret)))
		return
	elseif ret == 0 then
		if verbose() then
			log('[watchdog] disabled in systemd (WatchdogSec= not specified)')
		end
		return
	end
	local timeout = tonumber(timeoutptr[0]) / 1000  -- convert to ms
	local interval = timeout / 2  -- halve interval to make sure we are never late
	if interval < 1 then
		log('[watchdog] error: WatchdogSec= must be at least 2ms! (got %d usec)',
			tonumber(timeoutptr[0]))
	end
	watchdog.config({ interval = interval })
	if verbose() then
		log('[watchdog] systemd watchdog enabled (check interval: %s ms, timeout: %s ms)',
			private.interval, timeout)
	end
end

function watchdog.deinit()
	if private.event then
		event.cancel(private.event)
		private.event = nil
	end
end

return watchdog
