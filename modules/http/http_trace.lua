-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')
local condition = require('cqueues.condition')

-- Trace execution of DNS queries
local function serve_trace(h, _)
	local path = h:get(':path')
	local qname, qtype_str = path:match('/trace/([^/]+)/?([^/]*)')
	if not qname then
		return 400, 'expected /trace/<query name>/<query type>'
	end

	-- Parse query type (or default to A)
	if not qtype_str or #qtype_str == 0 then
		qtype_str = 'A'
	end

	local qtype = kres.type[qtype_str]
	if not qtype then
		return 400, string.format('unexpected query type: %s', qtype_str)
	end

	-- Create logging handler callback
	local buffer = {}
	local buffer_log_cb = ffi.cast('trace_log_f', function (_, msg)
		jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
		table.insert(buffer, ffi.string(msg))
	end)

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local cond = condition.new()
	local waiting, done = false, false
	local finish_cb = ffi.cast('trace_callback_f', function (req)
		jit.off(true, true) -- JIT for (C -> lua)^2 nesting isn't allowed
		table.insert(buffer, req:selected_tostring())
		if waiting then
			cond:signal()
		end
		done = true
	end)

	-- Resolve query and buffer logs into table
	resolve {
		name = qname,
		type = qtype,
		options = {'TRACE'},
		init = function (req)
			req:trace_chain_callbacks(buffer_log_cb, finish_cb)
		end
	}

	-- Wait for asynchronous query and free callbacks
	if not done then
		waiting = true
		cond:wait()
	end

	buffer_log_cb:free()
	finish_cb:free()

	-- Build the result
	local result = table.concat(buffer, '')
	-- Return buffered data
	if not done then
		return 504, result
	end
	return result
end

-- Export endpoints
return {
	endpoints = {
		['/trace']   = {'text/plain', serve_trace},
	}
}
