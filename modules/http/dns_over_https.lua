local condition = require('cqueues.condition')
local ffi = require('ffi')
local edns = require('edns')
local utils = require('utils')

-- Errors
local err_name_invalid =
	 'A valid query name must be set.'
local err_type_invalid =
	'RR type can be represented as a number in [1, 65535] or a canonical string (case-insensitive, such as A or aaaa).'
local err_flag_invalid =
	'Flag can be represented as a number in [0, 1] or a boolean [true, false].'
local err_dnssec_bogus =
	'"Comment": "DNSSEC validation failure. Please check http://dnsviz.net/d/%s/dnssec/"'

-- Section name formatting
local section_pretty_name = {
	[kres.section.ANSWER] = 'Answer',
	[kres.section.AUTHORITY] = 'Authority',
	[kres.section.ADDITIONAL] = 'Additional',
}

-- JSON escape table
local escape_char_map = {
  [ "\\" ] = "\\\\",
  [ "\"" ] = "\\\"",
  [ "\b" ] = "\\b",
  [ "\f" ] = "\\f",
  [ "\n" ] = "\\n",
  [ "\r" ] = "\\r",
  [ "\t" ] = "\\t",
}

local function escape_char(c)
	return escape_char_map[c] or string.format("\\u%04x", c:byte())
end

local function escape_string(val)
	if not val then return '' end
	return val:gsub('[%z\1-\31\\"]', escape_char)
end

-- Serialize a section to a JSON object array
local function section_tostring(pkt, section, min_ttl)
	local data = {}
	local records = pkt:rrsets(section)
	for _, rr in ipairs(records) do
		if rr.type ~= kres.type.OPT and rr.type ~= kres.type.TSIG then
			for i = 1, rr:rdcount() do
				-- Scan for minimum TTL in the packet
				if not min_ttl or rr:ttl() < min_ttl then
					min_ttl = rr:ttl()
				end
				-- Escape text values
				local rd = escape_string(rr:tostring(i - 1))
				table.insert(data, string.format(
					'{"name": "%s", "type": %d, "TTL": %d, "data": "%s"}',
					kres.dname2str(rr:owner()), rr.type, rr:ttl(), rd)
				)
			end
		end
	end
	return table.concat(data, ','), min_ttl
end


-- Serialize packet to a JSON object using the Google's DNS-over-HTTPS schema
-- https://developers.google.com/speed/public-dns/docs/dns-over-https
local function packet_tojson(pkt, bogus)
	local data = {}
	-- Serialise header
	table.insert(data, string.format('"Status": %d,"TC": %s,"RD": %s, "RA": %s, "AD": %s,"CD": %s',
		pkt:rcode(), pkt:tc(), pkt:rd(), pkt:ra(), pkt:ad(), pkt:cd()))
	-- Optional question
	local query_name = '.'
	if pkt:qdcount() > 0 then
		query_name = kres.dname2str(pkt:qname())
		table.insert(data, string.format('"Question":[{"name": "%s", "type": %d}]',
			query_name, pkt:qtype()))
	end
	-- Record sections
	local res, min_ttl
	for i = kres.section.ANSWER, tonumber(pkt.current) do
		res, min_ttl = section_tostring(pkt, i, min_ttl)
		if #res > 0 then
			res = string.format('"%s":[%s]', section_pretty_name[i], res)
			table.insert(data, res)
		end
	end
	-- DNSSEC validation state
	if bogus then
		table.insert(data, err_dnssec_bogus:format(query_name:sub(1, -2)))
	end
	return string.format('{%s}', table.concat(data, ',')), min_ttl
end



-- Map flag values to bit value
local flag_truth_table = {
	['1'] = true,
	['true'] = true,
	['0'] = false,
	['false'] = false,
}

local function parse_flag(v, dst, name)
	if not v then return end
	local ret = flag_truth_table[v]
	if ret == nil then
		return err_flag_invalid
	end
	if ret then
		table.insert(dst, name)
	end
end

-- Serve DNS-over-HTTPS request for application/dns-json
-- https://developers.google.com/speed/public-dns/docs/dns-over-https
local function serve_json(h, _, media_type)
	local path = h:get(':path')

	-- Parse query name
	local name = path:match('name=([^&]+)')
	if not name or #name > 254 or not kres.str2dname(name) then
		return 400, err_name_invalid
	end

	-- Parse query type, either a numeric value or  (or default to A)
	local query_type = path:match('type=([^&]+)')
	if query_type then
		-- The value is either string or numeric
		query_type = kres.type[string.upper(query_type)] or
			tonumber(query_type) or 0

		-- Check that the resolved type is valid
		if query_type < 1 or query_type > 65535 then
			return 400, err_type_invalid
		end
	else
		-- Default
		query_type = kres.type.A
	end

	-- Parse flags
	local flags = {}

	-- Parse DO flag
	local err = parse_flag(path:match('do=([^&]+)'), flags, 'DNSSEC_WANT')
	if err then
		return 400, err
	end
	-- Parse CD flag
	local err = parse_flag(path:match('cd=([^&]+)'), flags, 'DNSSEC_CD')
	if err then
		return 400, err
	end

	-- Track client address from x-forwarded-for
	local client_addr = h:get('x-forwarded-for')
	if client_addr then
		client_addr = ffi.gc(ffi.C.kr_straddr_socket(client_addr, 0), ffi.C.free)
	end

	-- Wait for the result of the query
	local result, min_ttl
	local cond = condition.new()
	local waiting, done = false, false
	resolve {
		name = name,
		type = query_type,
		init = function (req)
			local vars = kres.request_t(req):vars()
			-- Track internal DoH queries
			vars.request_doh_host = h:get(':authority')
			-- Track client address
			req.qsource.addr = client_addr
		end,
		finish = function (answer, req)
			local query = req:last()
			result, min_ttl = packet_tojson(answer, query and query.flags.DNSSEC_BOGUS)
			if waiting then
				cond:signal()
			end
			done = true
		end,
		options = flags,
	}

	-- Wait for asynchronous query and free callbacks
	if not done then
		waiting = true
		cond:wait()
	end

	-- Return buffered data
	if not done then
		return 504, result
	end

	return result, nil, media_type, min_ttl
end

-- Serve DNS-over-HTTPS request for application/dns-message
-- https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-10
local function serve_wireformat(h, stream, media_type)
	-- Only POST is supported currently
	local method = h:get(':method')
	if method ~= 'POST' then
		return 405
	end

	-- Parse packet and read question
	local body = stream:get_body_as_string()
	local pkt = kres.packet(#body, body)
	local ok = pkt:parse()
	if not ok then
		return 400
	end

	-- Track client address from x-forwarded-for
	local client_addr = h:get('x-forwarded-for')
	if client_addr then
		client_addr = ffi.gc(ffi.C.kr_straddr_socket(client_addr, 0), ffi.C.free)
	end

	-- Parse flags
	local flags = {}
	if edns.has_do(pkt.opt_rr) then
		table.insert(flags, 'DNSSEC_WANT')
	end
	if pkt:cd() then
		table.insert(flags, 'DNSSEC_CD')
	end


	-- Wait for the result of the query
	local result, min_ttl
	local cond = condition.new()
	local waiting, done = false, false
	resolve {
		name = kres.dname2str(pkt:qname()),
		type = pkt:qtype(),
		init = function (req)
			local vars = kres.request_t(req):vars()
			-- Track internal DoH queries
			vars.request_doh_host = h:get(':authority')
			-- Track client address
			req.qsource.addr = client_addr
		end,
		finish = function (answer, _)
			--- Keep original message ID
			answer:id(pkt:id())
			-- Copy response
			result = ffi.string(answer.wire, answer.size)
			min_ttl = utils.packet_minttl(answer)
			if waiting then
				cond:signal()
			end
			done = true
		end,
		options = flags,
	}

	-- Wait for asynchronous query and free callbacks
	if not done then
		waiting = true
		cond:wait()
	end

	-- Return buffered data
	if not done then
		return 504
	end

	return result, nil, media_type, min_ttl
end

-- Handlers for different supported media types
local content_type_handlers = {
   ['application/dns-udpwireformat'] = serve_wireformat, -- https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-03
   ['application/dns-message']       = serve_wireformat, -- https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-07
   ['application/dns-json']          = serve_json,
}


-- Serve content-negotiated DoH
local function serve_doh(h, stream)
	-- https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-09#section-5.1
	local media_type = h:get('content-type') or h:get('accept') or 'application/dns-message'
	media_type = media_type:match('[^;]+')
	local serve = content_type_handlers[media_type] or serve_wireformat
	return serve(h, stream, media_type)
end

-- Export endpoints
return {
	['/dns-query']   = {'application/dns-message', serve_doh},
	['/.well-known/dns-query']   = {'application/dns-message', serve_doh},
}
