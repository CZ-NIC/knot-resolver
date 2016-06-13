local cqueues = require('cqueues')

-- Load dependent modules
if not view then modules.load('view') end
if not policy then modules.load('policy') end

-- Actions
local actions = {
	pass = 1, deny = 2, drop = 3, tc = 4,
	forward = function (g)
		return policy.FORWARD(g())
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
		if op ~= '=' then error('source address supports only "=" operator') end
		return view.rule(true, g())
	end
}

local function parse_filter(tok, g)
	local filter = filters[tok:lower()]
	if not filter then error(string.format('invalid filter "%s"', tok)) end
	return filter(g)
end

local function parse_rule(g)
	local f = parse_filter(g(), g)
	-- Compose filter functions on conjunctions
	-- or terminate filter chain and return
	local tok = g()
	while tok do
		if tok == 'AND' then
			local fa, fb = f, parse_filter(g(), g)
			f = function (req, qry) return fa(req, qry) and fb(req, qry) end
		elseif tok == 'OR' then
			local fa, fb = f, parse_filter(g(), g)
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
	return filter, action, actid
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

-- Module declaration
local M = {
	rules = {}
}

-- @function Public-facing API
local function api(h, stream)
	local m = h:get(':method')
	-- GET method
	if m == 'GET' then
		local ret = {}
		for _, r in ipairs(M.rules) do
			table.insert(ret, {info=r.info, id=r.rule.id, count=r.rule.count})
		end
		return ret
	-- POST method
	elseif m == 'POST' then
		local query = stream:get_body_as_string()
		if query then
			local ok, r = pcall(M.add, query)
			if not ok then return 505 end
			return {info=r.info, id=r.rule.id, count=r.rule.count}
		end
		return 400
	end
end

-- @function Publish DAF statistics
local function publish(h, ws)
	local ok, counters = true, {}
	while ok do
		-- Check if we have new rule matches
		local update = {}
		for _, r in ipairs(M.rules) do
			local id = r.rule.id
			if counters[id] ~= r.rule.count then
				-- Must have string keys for JSON object and not an array
				update[tostring(id)] = r.rule.count
				counters[id] = r.rule.count
			end
		end
		-- Update counters when there is a new data
		if next(update) ~= nil then
			ws:send(tojson(update))
		end
		cqueues.sleep(2)
	end
	ws:close()
end

-- @function Cleanup module
function M.deinit()
	if http then
		http.endpoints['/daf'] = nil
		http.endpoints['/daf.js'] = nil
		http.snippets['/daf'] = nil
	end
end

-- @function Configure module
function M.config(conf)
	if not http then error('"http" module is not loaded, cannot load DAF') end
	-- Export API and data publisher
	http.endpoints['/daf.js'] = http.page('daf.js', 'daf')
	http.endpoints['/daf'] = {'application/json', api, publish}
	-- Export snippet
	http.snippets['/daf'] = {'Application Firewall', [[
		<script type="text/javascript" src="daf.js"></script>
		<div class="row">
			<form id="daf-builder-form">
				<div class="input-group">
					<input type="text" id="daf-builder" class="form-control" aria-label="..." />
					<div class="input-group-btn">
						<button type="button" id="daf-add" class="btn btn-default" style="margin-top: -5px;">Add</button>
					</div>
				</div>
			</form>
		</div>
		<div class="row">
			<table id="daf-rules" class="table table-striped table-responsive">
			<th><td>No rules here yet.</td></th>
			</table>
		</div>
	]]}
end

-- @function Add rule
function M.add(rule)
	local filter, action, id = compile(rule)
	if not filter then error(action) end
	-- Combine filter and action into policy
	local p = function (req, qry)
		return filter(req, qry) and action
	end
	local desc = {info=rule, policy=p}
	-- Enforce in policy module, special actions are postrules
	if id == 'reroute' or id == 'rewrite' then
		desc.rule = policy:add(p, true)
	else
		desc.rule = policy:add(p)
	end
	table.insert(M.rules, desc)
	return desc
end

return M