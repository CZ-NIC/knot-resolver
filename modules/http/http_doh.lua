local basexx = require('basexx')
local ffi = require('ffi')
local condition = require('cqueues.condition')

local function get_http_ttl(pkt)
	-- minimum TTL from all RRs in ANSWER
	if true then
		local an_records = pkt:section(kres.section.ANSWER)
		local is_negative = #an_records <= 0
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
	local input
	local method = h:get(':method')
	if method == 'POST' then
		input = stream:get_body_chars(65536, 10)  -- FIXME: timeout
	elseif method == 'GET' then
		local input_b64 = string.match(h:get(':path'), '^/doh%?dns=([a-zA-Z0-9_-]+)$')
		if not input_b64 then
			return 400, 'base64url query not found'
		end
		if #input_b64 > 87380 then  -- base64url encode 65535
			return 414, 'query parameter in URI too long'
		end
		input = basexx.from_url64(input_b64)
		if not input then
			return 400, 'invalid base64url'
		end
	else
		return 405, 'only HTTP POST and GET are supported'
	end

	if #input < 12 then
		return 400, 'input too short'
	elseif #input > 65535 then
		return 413, 'input too long'
	end

	local content_type = h:get('content-type') or 'application/dns-message'
	if content_type ~= 'application/dns-message' then
		return 415, 'only Content-Type: application/dns-message is supported'
	end
--	RFC 8484 section-4.1 allows us to ignore Accept header
--	local accept = h:get('accept') or 'application/dns-message'
--	if accept ~= 'application/dns-message' then
--		return 406, 'only Accept: application/dns-message is supported'
--	end

	-- Output buffer
	local output = ''

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local answers, authority = {}, {}
	local cond = condition.new()
	local waiting, done = false, false
	local finish_cb = function (answer, req)
		print(tostring(answer))  -- FIXME

		print('TTL: ', get_http_ttl(answer))

		-- binary output
		output = ffi.string(answer.wire, answer.size)
		if waiting then
			cond:signal()
		end
		done = true
	end

	-- convert query to knot_pkt_t
	local wire = ffi.cast("void *", input)
	local pkt = ffi.C.knot_pkt_new(wire, #input, nil);
	if not pkt then
		return 500, 'internal server error'
	end

	local result = ffi.C.knot_pkt_parse(pkt, 0)
	if result ~= 0 then
		return 400, 'unparseable DNS message'
	end
	print(pkt)

	-- resolve query
	worker.resolve_pkt(pkt, finish_cb)
	-- Wait for asynchronous query and free callbacks -- FIXME
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
