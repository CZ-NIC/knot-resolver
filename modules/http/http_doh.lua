-- SPDX-License-Identifier: GPL-3.0-or-later
local basexx = require('basexx')
local ffi = require('ffi')
local condition = require('cqueues.condition')

local function get_http_ttl(pkt)
	local an_records = pkt:section(kres.section.ANSWER)
	local is_negative = #an_records <= 0
	return ffi.C.packet_ttl(pkt, is_negative)
end

-- Trace execution of DNS queries
local function serve_doh(h, stream)
	local input
	local method = h:get(':method')
	if method == 'POST' then
		input = stream:get_body_chars(1025, 2)  -- read timeout = KR_CONN_RTT_MAX
	elseif method == 'GET' then
		local input_b64 = string.match(h:get(':path'), '^/doh%?dns=([a-zA-Z0-9_-]+)$') or
				string.match(h:get(':path'), '^/doh%?dns=([a-zA-Z0-9_-]+)&') or
				string.match(h:get(':path'), '^/doh%?.*&dns=([a-zA-Z0-9_-]+)$') or
				string.match(h:get(':path'), '^/doh%?.*&dns=([a-zA-Z0-9_-]+)&')
		if not input_b64 then
			return 400, 'base64url query not found'
		end
		if #input_b64 > 1368 then  -- base64url encode 1024
			return 414, 'query parameter in URI too long'
		end
		input = basexx.from_url64(input_b64)
		if not input then
			return 400, 'invalid base64url'
		end
	else
		return 405, 'only HTTP POST and GET are supported'
	end

	if not input or #input < 12 then
		return 400, 'input too short'
	elseif #input > 1024 then
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

	-- We get these values beforehand, because it's easier to handle errors now.
	local _, peer_addr, peer_port = stream:peername()
	local _, dst_addr, dst_port = stream:localname()
	if not (peer_addr and peer_port and dst_addr and dst_port) then
		 -- The connection probably died in the meantime or something.
		return 504, 'failed to determine your address'
	end

	-- Output buffer
	local output
	local output_ttl

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local cond = condition.new()
	local waiting, done = false, false
	local finish_cb = function (answer, _)
		output_ttl = get_http_ttl(answer)
		-- binary output
		output = ffi.string(answer.wire, answer.size)
		if waiting then
			cond:signal()
		end
		done = true
	end

	-- convert query to knot_pkt_t
	local wire = ffi.cast("void *", input)
	local pkt = ffi.gc(ffi.C.knot_pkt_new(wire, #input, nil), ffi.C.knot_pkt_free)
	if not pkt then
		return 500, 'internal server error'
	end

	local result = ffi.C.knot_pkt_parse(pkt, 0)
	if result ~= 0 then
		return 400, 'unparseable DNS message'
	end

	-- set source address so filters can work
	local function init_cb(req)
		req.qsource.addr = ffi.C.kr_straddr_socket(peer_addr, peer_port, req.pool)
		req.qsource.dst_addr = ffi.C.kr_straddr_socket(dst_addr, dst_port, req.pool)
		assert(req.qsource.addr ~= nil and req.qsource.dst_addr ~= nil)
		req.qsource.flags.tcp = true
		req.qsource.flags.tls = (stream.connection:checktls() ~= nil)
		req.qsource.flags.http = true
	end

	-- resolve query
	worker.resolve_pkt(pkt, {}, finish_cb, init_cb)
	if not done then
		waiting = true
		cond:wait()
	end

	-- Return buffered data
	if not done then
		return 504, 'huh?'  -- FIXME
	end
	return output, nil, 'application/dns-message', output_ttl
end

-- Export endpoints
return {
	endpoints = {
		['/doh']   = {'text/plain', serve_doh, nil, nil, true},
	}
}
