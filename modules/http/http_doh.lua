local ffi = require('ffi')
local condition = require('cqueues.condition')

local function get_http_ttl(pkt)
	-- minimum TTL from all RRs in ANSWER
	if true then
		local an_records = pkt:section(kres.section.ANSWER)
		local is_negative = #an_records <= 0
		-- FIXME: does not work for positive answers
		return ffi.C.packet_ttl(pkt, is_negative)
	end

	-- garbage
	if an_count > 0 then
		local min_ttl = 4294967295
		for i = 1, an_count do
			local rr = an_records[i]
			min_ttl = math.min(rr.ttl, min_ttl)
		end
		return min_ttl
	end

	-- no ANSWER records, try SOA
	local auth_records = pkt:section(kres.section.AUTHORITY)
	local auth_count = #auth_records
	if auth_count > 0 then
		for i = 1, an_count do
			local rr = an_records[i]
			if rr.type == kres.type.SOA then
				knot_soa_minimum()
			end
		end
		return 0  -- no SOA, uncacheable
	end
end

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
		print(tostring(answer))

		print('TTL: ', get_http_ttl(answer))

		-- binary output
		output = ffi.string(answer.wire, answer.size)
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
	-- worker.resolve("www.nic.cz", 666, KNOT_CLASS_IN, NULL, finish_cb)

	-- Wait for asynchronous query and free callbacks
	if not done then
		waiting = true
		cond:wait()
	end

	-- Return buffered data
	if not done then
		return 504, 'huh?'  -- FIXME
	end
	return output, nil, 'application/dns-message'
end

-- Export endpoints
return {
	endpoints = {
		['/doh']   = {'text/plain', serve_doh},
	}
}
