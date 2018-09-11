local ffi = require('ffi')
local bit = require('bit')
local condition = require('cqueues.condition')

-- Buffer selected record information to a table
local function add_selected_records(records)
	local dst = {}
	if #records == 0 then return dst end
	for _, rec in ipairs(records) do
		local rank = rec.rank
		-- Separate the referral chain verified flag
		local verified = bit.band(rec.rank, kres.rank.AUTH)
		if verified then
			rank = bit.band(rank, bit.bnot(kres.rank.AUTH))
		end
		local rank_name = kres.tostring.rank[rank] or tostring(rank)
		-- Write out each individual RR
		local owner = kres.dname2str(rec.rr:owner())
		local type_name = kres.tostring.type[rec.rr.type]
		for i = 1, rec.rr:rdcount() do
			local rd = rec.rr:tostring(i - 1)
			table.insert(dst,
				string.format('cached: %s, rank: %s, record: %s %s %d %s\n',
					tostring(rec.cached), rank_name:lower(), owner, type_name, rec.rr:ttl(), rd)
			)
		end
	end
	return dst
end

local function format_selected_records(header, records)
	if #records == 0 then return '' end
	return string.format('%s\n%s\n', header, string.rep('-', #header))
	       .. table.concat(records, '') .. '\n'
end

-- Log buffer
local function buffer_log(query, source, msg)
	local vars = query.request:vars()
	local message = string.format('[%5s] [%s] %s',
		query.id, ffi.string(source), ffi.string(msg))
	if not vars.trace_log  then
		vars.trace_log = {message}
	else
		table.insert(vars.trace_log, message)
	end
end

-- Create logging handler callback
local buffer_log_cb = ffi.cast('trace_log_f', buffer_log)

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

	local result = nil

	-- Wait for the result of the query
	-- Note: We can't do non-blocking write to stream directly from resolve callbacks
	-- because they don't run inside cqueue.
	local cond = condition.new()
	local waiting, done = false, false
	resolve {
		name = qname,
		type = qtype,
		init = function (req)
			req.trace_log = buffer_log_cb
		end,
		finish = function (_, req)
			local vars = req:vars()
			local answers = add_selected_records(req.answ_selected)
			local authority = add_selected_records(req.auth_selected)
			result = table.concat(vars.trace_log or {}, '') .. '\n'
			               .. format_selected_records('Used records from answer:', answers)
			               .. format_selected_records('Used records from authority:', authority)
			if waiting then
				cond:signal()
			end
			done = true
		end,
		options = {'TRACE'},
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
	return result
end

-- Export endpoints
return {
	endpoints = {
		['/trace']   = {'text/plain', serve_trace},
	}
}