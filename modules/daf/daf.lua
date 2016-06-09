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
	local filter = filters[tok]
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
	print('DAF: ')
	for k,v in h:each() do print(k,v) end
end

-- @function Publish DAF statistics
local function publish(h, ws)
	local ok = true
	while ok do
		-- Publish stats updates periodically
		local push = tojson({})
		ok = ws:send(push)
		cqueues.sleep(0.5)
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
		<table id="daf-rules"><th><td>No rules here yet.</td></th></table>
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
	table.insert(M.rules, {rule=rule, action=id, policy=p})
	-- Enforce in policy module, special actions are postrules
	if id == 'reroute' or id == 'rewrite' then
		table.insert(policy.postrules, p)
	else
		table.insert(policy.rules, p)
	end
end

return M