-- SPDX-License-Identifier: GPL-3.0-or-later

-- Load dependent modules
if not view then modules.load('view') end
if not policy then modules.load('policy') end

-- Actions
local actions = {
	pass = function() return policy.PASS end,
	deny = function () return policy.DENY end,
	drop = function() return policy.DROP end,
	tc = function() return policy.TC end,
	truncate = function() return policy.TC end,
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
}

-- Filter rules per column
local filters = {
	-- Filter on QNAME (either pattern or suffix match)
	qname = function (g)
		local op, val = g(), todname(g())
		if     op == '~' then return policy.pattern(true, val:sub(2)) -- Skip leading label length
		elseif op == '=' then return policy.suffix(true, {val})
		else error(string.format('invalid operator "%s" on qname', op)) end
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
	local filter = filters[tok:lower()]
	if not filter then error(string.format('invalid filter "%s"', tok)) end
	return filter(g)
end

local function parse_rule(g)
	-- Allow action without filter
	local tok = g()
	if tok == nil then
		error('empty rule is not allowed')
	end
	if not filters[tok:lower()] then
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
	if not actions[actid] then return nil, string.format('invalid action "%s"', actid) end
	-- Parse and interpret action
	local action = actions[actid]
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

-- Module declaration
local M = {
	rules = {}
}

-- @function Remove a rule

-- @function Cleanup module
function M.deinit()
	if http then
		local endpoints = http.configs._builtin.webmgmt.endpoints
		endpoints['/daf'] = nil
		endpoints['/daf.js'] = nil
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
	-- Enforce in policy module, special actions are postrules
	if id == 'reroute' or id == 'rewrite' then
		desc.rule = policy.add(p, true)
	else
		desc.rule = policy.add(p)
	end
	table.insert(M.rules, desc)
	return desc
end

-- @function Remove a rule
function M.del(id)
	for key, r in ipairs(M.rules) do
		if r.rule.id == id then
			policy.del(id)
			table.remove(M.rules, key)
			return true
		end
	end
	return nil
end

-- @function Find a rule
function M.get(id)
	for _, r in ipairs(M.rules) do
		if r.rule.id == id then
			return r
		end
	end
	return nil
end

-- @function Enable/disable a rule
function M.toggle(id, val)
	for _, r in ipairs(M.rules) do
		if r.rule.id == id then
			r.rule.suspended = not val
			return true
		end
	end
	return nil
end

-- @function Enable/disable a rule
function M.disable(id)
	return M.toggle(id, false)
end
function M.enable(id)
	return M.toggle(id, true)
end

local function consensus(op, ...)
	local ret = false
	local results = map(string.format(op, ...))
	for idx, r in ipairs(results) do
		if idx == 1 then
			-- non-empty table, init to true
			ret = true
		end
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
			if consensus('daf.del(%s)', id) then
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
			-- Dispatch to all other workers:
			-- we ignore return values except error() because they are not serializable
			consensus('daf.add "%s" and true', query)
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
	-- Must have string keys for JSON object and not an array
	local inst_counters = map('ret = {} '
		.. 'for _, rule in ipairs(daf.rules) do '
			.. 'ret[tostring(rule.rule.id)] = rule.rule.count '
		.. 'end '
		.. 'return ret')
	for inst_idx=1, inst_counters.n do
		for r_id, r_cnt in pairs(inst_counters[inst_idx]) do
			update[r_id] = (update[r_id] or 0) + r_cnt
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

function M.init()
	-- avoid ordering problem between HTTP and daf module
	event.after(0, M.config)
end

-- @function Configure module
function M.config()
	if not http then
		if verbose() then
			log('[daf ] HTTP API unavailable because HTTP module is not loaded, use modules.load("http")')
		end
		return
	end
	local endpoints = http.configs._builtin.webmgmt.endpoints
	-- Export API and data publisher
	endpoints['/daf.js'] = http.page('daf.js', 'daf')
	endpoints['/daf'] = {'application/json', api, publish}
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
