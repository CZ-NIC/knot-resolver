local kres = require('kres')
local policy = {
	-- Policies
	PASS = 1, DENY = 2, DROP = 3, TC = 4,
	-- Special values
	ANY = 0,
}

-- @function Requests which QNAME matches given zone list (i.e. suffix match)
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

-- @function Check for common suffix first, then suffix match (specialized version of suffix match)
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

-- @function policy QNAME pattern
function policy.pattern(action, pattern)
	return function(req, query)
		if string.find(query:name(), pattern) then
			return action
		end
		return nil
	end
end

-- @function Evaluate packet in given rules to determine policy action
function policy.evaluate(policy, req, query)
	for i = 1, #policy.rules do
		local action = policy.rules[i](req, query)
		if action ~= nil then
			return action
		end
	end
	return policy.PASS
end

-- @function Enforce policy action
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
	end
	return state
end

-- @function policy layer implementation
policy.layer = {
	begin = function(state, req)
		req = kres.request_t(req)
		local action = policy:evaluate(req, req:current())
		return policy.enforce(state, req, action)
	end
}

-- @function Add rule to policy list
function policy.add(policy, rule)
	return table.insert(policy.rules, rule)
end

-- @function Convert list of string names to domain names
function policy.to_domains(names)
	for i, v in ipairs(names) do
		names[i] = v:gsub('([^.]*%.)', function (x)
			return string.format('%s%s', string.char(x:len()-1), x:sub(1,-2))
		end)
	end
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
policy.to_domains(private_zones)

-- @var Default rules
policy.rules = { policy.suffix_common(policy.DENY, private_zones, '\4arpa') }

return policy
