-- Load dependent modules
if not view then modules.load('view') end
if not policy then modules.load('policy') end

-- Module declaration
local M = {
	rules = {},
	phases = {},
	actions = {},
	filters = {},
}

-- Phases for actions (e.g. when does the action execute)
-- The default phase is 'begin'
M.phases = {
	reroute = 'finish',
	rewrite = 'finish',
	features = 'checkout',
}

-- Actions
M.actions = {
	deny = function (_)
		return policy.DENY_MSG()
	end,
	drop = function (_)
		return policy.DROP
	end,
	refuse = function (_)
		return policy.REFUSE
	end,
	truncate = function (_)
		return policy.TC
	end,
	forward = function (g)
		local addrs = {}
		local tok = g()
		for addr in string.gmatch(tok, '[^,]+') do
			table.insert(addrs, addr)
		end
		return policy.FORWARD(addrs)
	end,
	mirror = function (g)
		return policy.MIRROR(g())
	end,
	reroute = function (g)
		local rules = {}
		local tok = g()
		while tok do
			local from, to = tok:match '([^-]+)-(%S+)'
			rules[from] = to
			tok = g()
		end
		return policy.REROUTE(rules)
	end,
	rewrite = function (g)
		local rules = {}
		local tok = g()
		while tok do
			-- This is currently limited to A/AAAA rewriting
			-- in fixed format '<owner> <type> <addr>'
			local _, to = g(), g()
			rules[tok] = to
			tok = g()
		end
		return policy.REROUTE(rules, true)
	end,
	features = function (g)
		local set_flags, clear_flags = {}, {}
		local allow_tcp = true
		-- Parse feature flag toggles
		-- Each feature can be prefixed with a symbol '+' or '-' (enable / disable)
		-- e.g. -dnssec +tcp .. disable DNSSEC, enable TCP
		local tok = g()
		while tok do
			local sign, o = tok:match '([+-])(%S+)'
			local enable = (sign ~= '-')
			if o == '0x20' then
				table.insert(enable and clear_flags or set_flags, 'NO_0X20')
			elseif o == 'tcp' then
				allow_tcp = enable
			elseif o == 'minimize' then
				table.insert(enable and clear_flags or set_flags, 'NO_MINIMIZE')
			elseif o == 'throttle' then
				table.insert(enable and clear_flags or set_flags, 'NO_THROTTLE')
			elseif o == 'edns' then
				table.insert(enable and clear_flags or set_flags, 'SAFEMODE')
			elseif o == 'dnssec' then
				-- This is a positive flag, so the the tables are interposed
				table.insert(enable and set_flags or clear_flags, 'DNSSEC_WANT')
			elseif o == 'permissive' then
				-- This is a positive flag, so the the tables are interposed
				table.insert(enable and set_flags or clear_flags, 'PERMISSIVE')
			else
				error('unknown feature: ' .. o)
			end
			tok = g()
		end
		-- Construct the action
		local set_flag_action = policy.FLAGS(set_flags, clear_flags)
		return function(state, req, qry, pkt, _ --[[addr]], is_stream)
			-- Track whether the minimization or 0x20 flag changes
			local had_0x20 = qry.flags.NO_0X20
			local had_minimize = qry.flags.NO_MINIMIZE
			set_flag_action(state, req, qry)
			-- Block outgoing TCP if disabled
			if not allow_tcp and is_stream then
				return kres.FAIL
			end
			-- Update outgoing message
			if qry.flags.NO_0X20 ~= had_0x20 or
			   qry.flags.NO_MINIMIZE ~= had_minimize then
				-- Update 0x20 secret to regenerate the QNAME randomization
				if qry.flags.NO_0X20 or qry.flags.SAFEMODE then
					qry.secret = 0
				else
					qry.secret = qry.secret + 1
				end
				local reserved = pkt.reserved
				local opt_rr = pkt.opt_rr
				qry:write(pkt)
				-- Restore space reservation and OPT
				pkt.reserved = reserved
				pkt.opt_rr = opt_rr
				pkt:begin(kres.section.ADDITIONAL)
			end
			return nil
		end
	end,
}

-- Filter rules per column
M.filters = {
	-- Filter on QTYPE
	qtype = function (g)
		local op, val = g(), g()
		local qtype = kres.type[val]
		if not qtype then
			error(string.format('invalid query type "%s"', val))
		end
		if op == '=' then return policy.query_type(true, {qtype})
		else error(string.format('invalid operator "%s" on qtype', op)) end
	end,
	-- Filter on QNAME (either pattern or suffix match)
	qname = function (g)
		local op, val = g(), todname(g())
		if     op == '~' then return policy.pattern(true, val:sub(2)) -- Skip leading label length
		elseif op == '=' then return policy.suffix(true, {val})
		else error(string.format('invalid operator "%s" on qname', op)) end
	end,
	-- Filter on NS
	ns = function (g)
		local op, val = g(), todname(g())
		if op == '=' then return policy.ns_suffix(true, {val})
		else error(string.format('invalid operator "%s" on ns', op)) end
	end,
	-- Filter on source address
	src = function (g)
		local op = g()
		if op ~= '=' then error('address supports only "=" operator') end
		return view.rule_src(true, g())
	end,
	-- Filter on destination address
	dst = function (g)
		local op = g()
		if op ~= '=' then error('address supports only "=" operator') end
		return view.rule_dst(true, g())
	end,
}

local function parse_filter(tok, g, prev)
	if not tok then error(string.format('expected filter after "%s"', prev)) end
	local filter = M.filters[tok:lower()]
	if not filter then error(string.format('invalid filter "%s"', tok)) end
	return filter(g)
end

local function parse_rule(g)
	-- Allow action without filter
	local tok = g()
	if not M.filters[tok:lower()] then
		return tok, nil
	end
	local f = parse_filter(tok, g)
	-- Compose filter functions on conjunctions
	-- or terminate filter chain and return
	tok = g()
	while tok do
		if tok:lower() == 'and' then
			local fa, fb = f, parse_filter(g(), g, tok)
			f = function (req, qry) return fa(req, qry) and fb(req, qry) end
		elseif tok:lower() == 'or' then
			local fa, fb = f, parse_filter(g(), g, tok)
			f = function (req, qry) return fa(req, qry) or fb(req, qry) end
		else
			break
		end
		tok = g()
	end
	return tok, f
end

local function parse_query(g)
	local ok, actid, filter = pcall(parse_rule, g)
	if not ok then return nil, actid end
	actid = actid:lower()
	if not M.actions[actid] then
		return nil, string.format('invalid action "%s"', actid)
	end
	-- Parse and interpret action
	local action = M.actions[actid]
	if type(action) == 'function' then
		action = action(g)
	end
	return actid, action, filter
end

-- Compile a rule described by query language
-- The query language is modelled by iptables/nftables
-- conj = AND | OR
-- op = IS | NOT | LIKE | IN
-- filter = <key> <op> <expr>
-- rule = <filter> | <filter> <conj> <rule>
-- action = PASS | DENY | DROP | TC | FORWARD
-- query = <rule> <action>
local function compile(query)
	local g = string.gmatch(query, '%S+')
	return parse_query(g)
end

-- @function Describe given rule for presentation
local function rule_info(r)
	return {info=r.info, id=r.rule.id, active=(r.rule.suspended ~= true), count=r.rule.count}
end

-- @function Remove a rule

-- @function Cleanup module
function M.deinit()
	if http and http.endpoints then
		http.endpoints['/daf'] = nil
		http.endpoints['/daf.js'] = nil
		http.snippets['/daf'] = nil
	end
end

-- @function Add rule
function M.add(rule)
	-- Ignore duplicates
	for _, r in ipairs(M.rules) do
		if r.info == rule then return r end
	end
	local id, action, filter = compile(rule)
	if not id then error(action) end
	-- Combine filter and action into policy
	local p
	if filter then
		p = function (req, qry)
			return filter(req, qry) and action
		end
	else
		p = function ()
			return action
		end
	end
	local desc = {info=rule, policy=p}
	-- Enforce in policy module in given phase
	local phase = M.phases[id] or 'begin'
	desc.rule = policy.add(p, phase)
	table.insert(M.rules, desc)
	return desc
end

-- @function Remove a rule
function M.del(id)
	for _, r in ipairs(M.rules) do
		if r.rule.id == id then
			policy.del(id)
			table.remove(M.rules, id)
			return true
		end
	end
end

-- @function Find a rule
function M.get(id)
	for _, r in ipairs(M.rules) do
		if r.rule.id == id then
			return r
		end
	end
end

-- @function Enable/disable a rule
function M.toggle(id, val)
	for _, r in ipairs(M.rules) do
		if r.rule.id == id then
			r.rule.suspended = not val
			return true
		end
	end
end

-- @function Enable/disable a rule
function M.disable(id)
	return M.toggle(id, false)
end
function M.enable(id)
	return M.toggle(id, true)
end

local function consensus(op, ...)
	local ret = true
	local results = map(string.format(op, ...))
	for _, r in ipairs(results) do
		ret = ret and r
	end
	return ret
end

-- @function Public-facing API
local function api(h, stream)
	local m = h:get(':method')
	-- GET method
	if m == 'GET' then
		local path = h:get(':path')
		local id = tonumber(path:match '/([^/]*)$')
		if id then
			local r = M.get(id)
			if r then
				return rule_info(r)
			end
			return 404, '"No such rule"' -- Not found
		else
			local ret = {}
			for _, r in ipairs(M.rules) do
				table.insert(ret, rule_info(r))
			end
			return ret
		end
	-- DELETE method
	elseif m == 'DELETE' then
		local path = h:get(':path')
		local id = tonumber(path:match '/([^/]*)$')
		if id then
			if consensus('daf.del "%s"', id) then
				return tojson(true)
			end
			return 404, '"No such rule"' -- Not found
		end
		return 400 -- Request doesn't have numeric id
	-- POST method
	elseif m == 'POST' then
		local query = stream:get_body_as_string()
		if query then
			local ok, r = pcall(M.add, query)
			if not ok then return 500, string.format('"%s"', r:match('/([^/]+)$')) end
			-- Dispatch to all other workers
			consensus('daf.add "%s"', query)
			return rule_info(r)
		end
		return 400
	-- PATCH method
	elseif m == 'PATCH' then
		local path = h:get(':path')
		local id, action, val = path:match '(%d+)/([^/]*)/([^/]*)$'
		id = tonumber(id)
		if not id or not action or not val then
			return 400 -- Request not well formatted
		end
		-- We do not support more actions
		if action == 'active' then
			if consensus('daf.toggle(%d, %s)', id, val == 'true' or 'false') then
				return tojson(true)
			else
				return 404, '"No such rule"'
			end
		else
			return 501, '"Action not implemented"'
		end
	end
end

local function getmatches()
	local update = {}
	for _, rules in ipairs(map 'daf.rules') do
		for _, r in ipairs(rules) do
			local id = tostring(r.rule.id)
			-- Must have string keys for JSON object and not an array
			update[id] = (update[id] or 0) + r.rule.count
		end
	end
	return update
end

-- @function Publish DAF statistics
local function publish(_, ws)
	local ok, last = true, nil
	while ok do
		-- Check if we have new rule matches
		local diff = {}
		local has_update, update = pcall(getmatches)
		if has_update then
			if last then
				for id, count in pairs(update) do
					if not last[id] or last[id] < count then
						diff[id] = count
					end
				end
			end
			last = update
		end
		-- Update counters when there is a new data
		if next(diff) ~= nil then
			ok = ws:send(tojson(diff))
		else
			ok = ws:send_ping()
		end
		worker.sleep(1)
	end
end

-- @function Configure module
function M.config()
	if not http or not http.endpoints then return end
	-- Export API and data publisher
	http.endpoints['/daf.js'] = http.page('daf.js', 'daf')
	http.endpoints['/daf'] = {'application/json', api, publish}
	-- Export snippet
	http.snippets['/daf'] = {'Application Firewall', [[
		<script type="text/javascript" src="daf.js"></script>
		<div class="row" style="margin-bottom: 5px">
			<form id="daf-builder-form">
				<div class="col-md-11">
					<input type="text" id="daf-builder" class="form-control" aria-label="..." />
				</div>
				<div class="col-md-1">
					<button type="button" id="daf-add" class="btn btn-default btn-sm">Add</button>
				</div>
			</form>
		</div>
		<div class="row">
			<div class="col-md-12">
				<table id="daf-rules" class="table table-striped table-responsive">
				<th><td>No rules here yet.</td></th>
				</table>
			</div>
		</div>
	]]}
end

return M