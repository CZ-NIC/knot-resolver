local kres = require('kres')
local block = {
	-- Policies
	PASS = 1, DENY = 2, DROP = 3,
	-- Special values
	ANY = 0,
}

-- @function Block requests which QNAME matches given zone list (i.e. suffix match)
function block.suffix(action, zone_list)
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
function block.suffix_common(action, suffix_list, common_suffix)
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

-- @function Block QNAME pattern
function block.pattern(action, pattern)
	return function(req, query)
		if string.find(query:name(), pattern) then
			return action
		end
		return nil
	end
end

-- @function Evaluate packet in given rules to determine block action
function block.evaluate(block, req, query)
	for i = 1, #block.rules do
		local action = block.rules[i](req, query)
		if action ~= nil then
			return action
		end
	end
	return block.PASS
end

-- @function Block layer implementation
block.layer = {
	begin = function(state, req)
		req = kres.request_t(req)
		local action = block:evaluate(req, req:current())
		if action == block.DENY then
			-- Write authority information
			local answer = req.answer
			answer:rcode(kres.rcode.NXDOMAIN)
			answer:begin(kres.section.AUTHORITY)
			answer:put('\5block', 900, answer:qclass(), kres.type.SOA,
				'\5block\0\0\0\0\0\0\0\0\14\16\0\0\3\132\0\9\58\128\0\0\3\132')
			return kres.DONE
		elseif action == block.DROP then
			return kres.FAIL
		end
		return state
	end
}

-- @function Add rule to block list
function block.add(block, rule)
	return table.insert(block.rules, rule)
end

-- @function Convert list of string names to domain names
function block.to_domains(names)
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
block.to_domains(private_zones)

-- @var Default rules
block.rules = { block.suffix_common(block.DENY, private_zones, '\4arpa') }

return block
