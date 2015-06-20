local block = {
	-- Policies
	PASS = 1, DENY = 2, DROP = 3,
	-- Special values
	ANY = 0,
	-- Private, local, broadcast, test and special zones 
	private_zones = {
		-- RFC1918
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
}

-- @function Block requests which QNAME matches given zone list (i.e. suffix match)
function block.suffix(action, zone_list)
	local AC = require('aho-corasick')
	local tree = AC.build(zone_list)
	return function(pkt, qry)
		local qname = qry:qname()
		local match = AC.match(tree, qname, false)
		if next(match) ~= nil then
			return action, match[1]
		end
		return nil
	end
end

-- @function Block QNAME pattern
function block.pattern(action, pattern)
	return function(pkt, qry)
		local qname = qry:qname()
		if string.find(qname, pattern) then
			return action, qname
		end
		return nil
	end
end

-- @function Evaluate packet in given rules to determine block action
function block.evaluate(block, pkt, qry)
	for _,rule in pairs(block.rules) do
		local action, authority = rule(pkt, qry)
		if action ~= nil then
			return action, authority
		end
	end
	return block.PASS, nil
end

-- @function Block layer implementation
block.layer = {
	produce = function(state, req, pkt)
		-- Only when a query isn't already answered
		if state ~= kres.CONSUME then
			return state
		end
		-- Interpret packet in Lua and evaluate
		local qry = kres.query_current(req)
		local action, authority = block:evaluate(pkt, qry)
		if action == block.DENY then
			-- Answer full question
			qry:flag(kres.query.NO_MINIMIZE)
			pkt:question(qry:qname(), qry:qclass(), qry:qtype())
			pkt:flag(kres.wire.QR)
			pkt:flag(kres.wire.AA)
			-- Write authority information
			pkt:rcode(kres.rcode.NXDOMAIN)
			pkt:begin(kres.AUTHORITY)
			pkt:add(authority, qry:qclass(), kres.rrtype.SOA, 900,
				'\5block\0\0'..'\0\0\0\0'..'\0\0\14\16'..'\0\0\3\132'..'\0\9\58\128'..'\0\0\3\132')
			return kres.DONE
		elseif action == block.DROP then
			return kres.FAIL
		else
			return state
		end
	end
}

-- @var Default rules
block.rules = { block.suffix(block.DENY, block.private_zones) }

-- @function Add rule to block list
function block.add(block, rule)
	return table.insert(block.rules, rule)
end

return block
