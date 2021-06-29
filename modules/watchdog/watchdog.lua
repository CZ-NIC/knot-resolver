-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

ffi.cdef([[
	int sd_watchdog_enabled(int unset_environment, uint64_t *usec);
	int sd_notify(int unset_environment, const char *state);
	void abort(void);
]])

local watchdog = {}
local private = {}

local function sd_signal_ok()
	ffi.C.sd_notify(0, 'WATCHDOG=1')
end

function private.fail_callback()
	log_error(ffi.C.WATCHDOG, 'ABORTING resolver, supervisor is expected to restart it')
	ffi.C.abort()
end

-- logging
local function add_tracer(logbuf)
	return function (req)
		local function qrylogger(_, msg)
			jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
			table.insert(logbuf, ffi.string(msg))
		end
		req.trace_log = ffi.cast('trace_log_f', qrylogger)
	end
end

local function check_answer(logbuf)
	return function (pkt, req)
		req.trace_log:free()
		if pkt ~= nil and (pkt:rcode() == kres.rcode.NOERROR
							or pkt:rcode() == kres.rcode.NXDOMAIN) then
			private.ok_callback()
			return
		end
		log_info(ffi.C.WATCHDOG, 'watchdog query returned unexpected answer! query verbose log:')
		log_info(ffi.C.WATCHDOG, table.concat(logbuf, ''))
		if pkt ~= nil then
			log_info(ffi.C.WATCHDOG, 'problematic answer:\n%s', pkt)
		else
			log_info(ffi.C.WATCHDOG, 'answer was dropped')
		end
		-- failure! quit immediatelly to allow process supervisor to restart us
		private.fail_callback()
	end
end
private.check_answer_callback = check_answer

local function timer()
	local logbuf = {}
	-- fire watchdog query
	if private.qname and private.qtype then
		log_info(ffi.C.WATCHDOG, 'starting watchdog query %s %s', private.qname, private.qtype)
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

	local interval = tonumber(cfg.interval or private.interval or 10000)
	if not interval or interval < 1 then
		error('[watchdog] interval must be >= 1 ms')
	end
	private.interval = interval

	-- qname = nil will disable DNS queries
	private.qname = cfg.qname
	private.qtype = cfg.qtype or kres.type.A

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
		log_info(ffi.C.WATCHDOG, 'systemd library not detected')
		return
	end
	private.ok_callback = sd_signal_ok
	if ret < 0 then
		error('[watchdog] %s', ffi.string(ffi.C.knot_strerror(math.abs(ret))))
		return
	elseif ret == 0 then
		log_info(ffi.C.WATCHDOG, 'disabled in systemd (WatchdogSec= not specified)')
		return
	end
	local timeout = tonumber(timeoutptr[0]) / 1000  -- convert to ms
	local interval = timeout / 2  -- halve interval to make sure we are never late
	if interval < 1 then
		log_error(ffi.C.WATCHDOG, 'error: WatchdogSec= must be at least 2ms! (got %d usec)',
			tonumber(timeoutptr[0]))
	end
	watchdog.config({ interval = interval })
	log_info(ffi.C.WATCHDOG, 'systemd watchdog enabled (check interval: %s ms, timeout: %s ms)',
		private.interval, timeout)
end

function watchdog.deinit()
	if private.event then
		event.cancel(private.event)
		private.event = nil
	end
end

return watchdog
