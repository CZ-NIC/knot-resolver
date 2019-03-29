local ffi = require('ffi')
local condition = require('cqueues.condition')

-- Trace execution of DNS queries
local function serve_doh(h, stream)
	local path = h:get(':path')
	local input = stream:get_body_as_string(10)  -- FIXME: timeout
	-- Output buffer
	local output = ''

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local answers, authority = {}, {}
	local cond = condition.new()
	local waiting, done = false, false
	local finish_cb = function (answer, req)
		output = tostring(answer)
		if waiting then
			cond:signal()
		end
		done = true
	end

	-- Resolve query
	wire = ffi.cast("void *", input)
	local pkt = ffi.C.knot_pkt_new(wire, #input, nil);
	if not pkt then
		output = 'shit happened in knot_pkt_new'
	else
		output = 'knot_pkt_new ok'
	end

	local result = ffi.C.knot_pkt_parse(pkt, 0)
	if result > 0 then
		output = output .. '\nshit in knot_pkt_parse'
	else
		output = output .. '\nknot_pkt_parse ok'
	end
	print(pkt)
	print(output)
	worker.resolve_pkt(pkt, finish_cb)

	-- Wait for asynchronous query and free callbacks
	if not done then
		waiting = true
		cond:wait()
	end

	-- Return buffered data
	if not done then
		return 504, 'huh?'
	end
	return output
end

-- Export endpoints
return {
	endpoints = {
		['/doh']   = {'text/plain', serve_doh},
	}
}
