local cqueues = require('cqueues')

-- Load dependent modules
if not view then modules.load('view') end
if not policy then modules.load('policy') end

-- Actions
local actions = {
	pass = 1, deny = 2, drop = 3, tc = 4, forward = policy.FORWARD,
}

-- Filter rules per column
local filters = {
	-- Filter on QNAME (either pattern or suffix match)
	qname = function (g)
		local op, val = g(), todname(g())
		if     op == '~' then return policy.pattern(true, val)
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
			local fnext = parse_filter(g(), g)
			f = function (req, qry) return f(req, qry) and fnext(req, qry) end
		elseif tok == 'OR' then
			local fnext = parse_filter(g(), g)
			f = function (req, qry) return f(req, qry) or fnext(req, qry) end
		else
			break
		end
		tok = g()
		print('next token is', tok)
	end
	return tok, f
end

local function parse_query(g)
	local ok, action, filter = pcall(parse_rule, g)
	if not ok then return nil, action end
	if not actions[action] then return nil, string.format('invalid action "%s"', action) end
	-- Parse and interpret action
	action = actions[action]
	if type(action) == 'function' then
		action = action(g())
	end
	return action, filter
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
		http.snippets['/daf'] = nil
	end
end

-- @function Configure module
function M.config(conf)
	if not http then error('"http" module is not loaded, cannot load DAF') end
	-- Export API and data publisher
	http.endpoints['/daf'] = {'application/json', api, publish}
	-- Export snippet
	http.snippets['/daf'] = {'Application Firewall', [[
		<p>Hello world!</p>
	]]}
	M.rule('qname = *.example.com AND src = 127.0.0.1/8 deny')
	-- M.rule('answer ~ (%w+).facebook.com AND src = 127.0.0.1/8 forward 8.8.8.8')
end

-- @function Add rule
function M.rule(rule)
	local action, filter = compile(rule)
	if not action then error(filter) end
	table.insert(M.rules, {rule, action, filter})
	print(action, filter, rule)
end

return M