local kres = require('kres')

-- Counter of unique rules
local nextid = 0
local function getruleid()
	local newid = nextid
	nextid = nextid + 1
	return newid
end

-- Forward request, and solve as stub query
local function forward(target)
	local dst_ip = kres.str2ip(target)
	if dst_ip == nil then error("FORWARD target '"..target..'" is not a valid IP address') end
	return function(state, req)
		req = kres.request_t(req)
		local qry = req:current()
		qry.flags = qry.flags + kres.query.STUB
		qry:nslist(dst_ip)
		return state
	end
end

-- Rewrite records in packet
local function reroute(tbl, names)
	-- Import renumbering rules
	local ren = require('renumber')
	local prefixes = {}
	for from, to in pairs(tbl) do
		table.insert(prefixes, names and ren.name(from, to) or ren.prefix(from, to))
	end
	-- Return rule closure
	tbl = nil
	return ren.rule(prefixes)
end

local policy = {
	-- Policies
	PASS = 1, DENY = 2, DROP = 3, TC = 4, FORWARD = forward, REROUTE = reroute,
	-- Special values
	ANY = 0,
}

-- All requests
function policy.all(action)
	return function(req, query) return action end
end

-- Requests which QNAME matches given zone list (i.e. suffix match)
function policy.suffix(action, zone_list)
	local AC = require('aho-corasick')
	local tree = AC.build(zone_list)
	return function(req, query)
		local match = AC.match(tree, query:name(), false)
		if match[1] ~= nil then
			return action
		end
		return nil
	end
end

-- Check for common suffix first, then suffix match (specialized version of suffix match)
function policy.suffix_common(action, suffix_list, common_suffix)
	local common_len = string.len(common_suffix)
	local suffix_count = #suffix_list
	return function(req, query)
		-- Preliminary check
		local qname = query:name()
		if not string.find(qname, common_suffix, -common_len, true) then
			return nil
		end
		-- String match
		for i = 1, suffix_count do
			local zone = suffix_list[i]
			if string.find(qname, zone, -string.len(zone), true) then
				return action
			end
		end
		return nil
	end
end

-- Filter QNAME pattern
function policy.pattern(action, pattern)
	return function(req, query)
		if string.find(query:name(), pattern) then
			return action
		end
		return nil
	end
end

local function rpz_parse(action, path)
	local rules = {}
	local ffi = require('ffi')
	local action_map = {
		-- RPZ Policy Actions
		['\0'] = action,
		['\1*\0'] = action, -- deviates from RPZ spec
		['\012rpz-passthru\0'] = policy.PASS, -- the grammar...
		['\008rpz-drop\0'] = policy.DROP,
		['\012rpz-tcp-only\0'] = policy.TC,
		-- Policy triggers @NYI@
	}
	local parser = require('zonefile').new()
	if not parser:open(path) then error(string.format('failed to parse "%s"', path)) end
	while parser:parse() do
		local name = ffi.string(parser.r_owner, parser.r_owner_length)
		local action = ffi.string(parser.r_data, parser.r_data_length)
		rules[name] = action_map[action]
		-- Warn when NYI
		if #name > 1 and not action_map[action] then
			print(string.format('[ rpz ] %s:%d: unsupported policy action', path, tonumber(parser.line_counter)))
		end
	end
	return rules
end

-- Create RPZ from zone file
local function rpz_zonefile(action, path)
	local rules = rpz_parse(action, path)
	collectgarbage()
	return function(req, query)
		local label = query:name()
		local action = rules[label]
		while action == nil and string.len(label) > 0 do
			label = string.sub(label, string.byte(label) + 2)
			action = rules['\1*'..label]
		end
		return action
	end
end

-- RPZ policy set
function policy.rpz(action, path, format)
	if format == 'lmdb' then
		error('lmdb zone format is NYI')
	else
		return rpz_zonefile(action, path)
	end
end

-- Evaluate packet in given rules to determine policy action
function policy.evaluate(rules, req, query)
	for i = 1, #rules do
		local rule = rules[i]
		local action = rule.cb(req, query)
		if action ~= nil then
			rule.count = rule.count + 1
			return action
		end
	end
	return policy.PASS
end

-- Enforce policy action
function policy.enforce(state, req, action)
	if action == policy.DENY then
		-- Write authority information
		local answer = req.answer
		answer:rcode(kres.rcode.NXDOMAIN)
		answer:begin(kres.section.AUTHORITY)
		answer:put('\7blocked', 900, answer:qclass(), kres.type.SOA,
			'\7blocked\0\0\0\0\0\0\0\0\14\16\0\0\3\132\0\9\58\128\0\0\3\132')
		return kres.DONE
	elseif action == policy.DROP then
		return kres.FAIL
	elseif action == policy.TC then
		local answer = req.answer
		if answer.max_size ~= 65535 then
			answer:tc(1) -- ^ Only UDP queries
			return kres.DONE
		end
	elseif type(action) == 'function' then
		return action(state, req)
	end
	return state
end

-- Capture queries before processing
policy.layer = {
	begin = function(state, req)
		req = kres.request_t(req)
		local action = policy.evaluate(policy.rules, req, req:current())
		return policy.enforce(state, req, action)
	end,
	finish = function(state, req)
		req = kres.request_t(req)
		local action = policy.evaluate(policy.postrules, req, req:current())
		return policy.enforce(state, req, action)
	end
}

-- Add rule to policy list
function policy.add(policy, rule, postrule)
	local desc = {id=getruleid(), cb=rule, count=0}
	table.insert(postrule and policy.postrules or policy.rules, desc)
	return desc
end

-- Convert list of string names to domain names
function policy.todnames(names)
	for i, v in ipairs(names) do
		names[i] = kres.str2dname(v)
	end
	return names
end

-- RFC1918 Private, local, broadcast, test and special zones 
local private_zones = {
	'10.in-addr.arpa.',
	'16.172.in-addr.arpa.',
	'17.172.in-addr.arpa.',
	'18.172.in-addr.arpa.',
	'19.172.in-addr.arpa.',
	'20.172.in-addr.arpa.',
	'21.172.in-addr.arpa.',
	'22.172.in-addr.arpa.',
	'23.172.in-addr.arpa.',
	'24.172.in-addr.arpa.',
	'25.172.in-addr.arpa.',
	'26.172.in-addr.arpa.',
	'27.172.in-addr.arpa.',
	'28.172.in-addr.arpa.',
	'29.172.in-addr.arpa.',
	'30.172.in-addr.arpa.',
	'31.172.in-addr.arpa.',
	'168.192.in-addr.arpa.',
	-- RFC5735, RFC5737
	'0.in-addr.arpa.',
	'127.in-addr.arpa.',
	'254.169.in-addr.arpa.',
	'2.0.192.in-addr.arpa.',
	'100.51.198.in-addr.arpa.',
	'113.0.203.in-addr.arpa.',
	'255.255.255.255.in-addr.arpa.',
	-- IPv6 local, example
	'0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.',
	'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.',
	'd.f.ip6.arpa.',
	'8.e.f.ip6.arpa.',
	'9.e.f.ip6.arpa.',
	'a.e.f.ip6.arpa.',
	'b.e.f.ip6.arpa.',
	'8.b.d.0.1.0.0.2.ip6.arpa',
}
policy.todnames(private_zones)

-- @var Default rules
policy.rules = {}
policy.postrules = {}
policy:add(policy.suffix_common(policy.DENY, private_zones, '\4arpa\0'))

return policy
