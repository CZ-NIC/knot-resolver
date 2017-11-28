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
	local buffer_log_cb = ffi.cast('trace_log_f', function (_, source, msg)
		local message = string.format('%4s | %s', ffi.string(source), ffi.string(msg))
		table.insert(buffer, message)
	end)

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local cond = condition.new()
	local done = false

	-- Resolve query and buffer logs into table
	resolve {
		name = qname,
		type = qtype,
		options = {'TRACE'},
		begin = function (req)
			req = kres.request_t(req)
			req.trace_log = buffer_log_cb
		end,
		finish = function ()
			cond:signal()
			done = true
		end
	}

	-- Wait for asynchronous query and free callbacks
	if done then
		cond:wait(0) -- Must pick up the signal
	else
		cond:wait()
	end
	buffer_log_cb:free()

	-- Return buffered data
	local result = table.concat(buffer, '') .. '\n'
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