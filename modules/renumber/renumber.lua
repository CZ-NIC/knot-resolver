-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface
local ffi = require('ffi')
local prefixes_global = {}

-- Create subnet prefix rule
local function matchprefix(subnet, addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	local subnet_cd = ffi.new('char[16]')
	local bitlen = ffi.C.kr_straddr_subnet(subnet_cd, subnet)
	if bitlen < 0 then error('[renumber] invalid subnet: '..subnet) end
	return {subnet_cd, bitlen, target, addrtype}
end

-- Create name match rule
local function matchname(name, addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local owner = todname(name)
	if not name then error('[renumber] invalid name: '..name) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	return {owner, nil, target, addrtype}
end

-- Add subnet prefix rewrite rule
local function add_prefix(subnet, addr)
	local prefix = matchprefix(subnet, addr)
	local bitlen = prefix[2]
	if bitlen ~= nil and bitlen % 8 ~= 0 then
		log_warn(ffi.C.LOG_GRP_RENUMBER, 'network mask: only /8, /16, /24 etc. are supported (entire octets are rewritten)')
	end
	table.insert(prefixes_global, prefix)
end

-- Match IP against given subnet or record owner
local function match_subnet(subnet, bitlen, addrtype, rr)
	local addr = rr.rdata
	return addrtype == rr.type and
	       ((bitlen and (#addr >= bitlen / 8) and (ffi.C.kr_bitcmp(subnet, addr, bitlen) == 0)) or subnet == rr.owner)
end

-- Renumber address record
local addr_buf = ffi.new('char[16]')
local function renumber_record(tbl, rr)
	for i = 1, #tbl do
		local prefix = tbl[i]
		-- Match record type to address family and record address to given subnet
		-- If provided, compare record owner to prefix name
		if match_subnet(prefix[1], prefix[2], prefix[4], rr) then
			-- Replace part or whole address
			local to_copy = prefix[2] or (#prefix[3] * 8)
			local chunks = to_copy / 8
			local rdlen = #rr.rdata
			if rdlen < chunks then return rr end -- Address length mismatch
			ffi.copy(addr_buf, rr.rdata, rdlen)
			ffi.copy(addr_buf, prefix[3], chunks) -- Rewrite prefix
			rr.rdata = ffi.string(addr_buf, rdlen)
			return rr
		end
	end
	return nil
end

-- Renumber addresses based on config
local function rule(prefixes)
	return function (state, req)
		if state == kres.FAIL then return state end
		local pkt = req.answer
		-- Only successful answers
		local records = pkt:section(kres.section.ANSWER)
		local ancount = #records
		if ancount == 0 then return state end
		-- Find renumber candidates
		local changed = false
		for i = 1, ancount do
			local rr = records[i]
			if rr.type == kres.type.A or rr.type == kres.type.AAAA then
				local new_rr = renumber_record(prefixes, rr)
				if new_rr ~= nil then
					records[i] = new_rr
					changed = true
				end
			end
		end
		-- If not rewritten, chain action
		if not changed then return state end
		-- Replace section if renumbering
		local qname = pkt:qname()
		local qclass = pkt:qclass()
		local qtype = pkt:qtype()
		pkt:recycle()
		pkt:question(qname, qclass, qtype)
		for i = 1, ancount do
			local rr = records[i]
			-- Strip signatures as rewritten data cannot be validated
			if rr.type ~= kres.type.RRSIG then
				pkt:put(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
			end
		end
		req:set_extended_error(kres.extended_error.FORGED, "DUQR")
		return state
	end
end

-- Export module interface
local M = {
	prefix = matchprefix,
	name = matchname,
	rule = rule,
	match_subnet = match_subnet,
}

-- Config
function M.config (conf)
	if conf == nil then return end
	if type(conf) ~= 'table' or type(conf[1]) ~= 'table' then
		error('[renumber] expected { {prefix, target}, ... }')
	end
	for i = 1, #conf do add_prefix(conf[i][1], conf[i][2]) end
end

-- Layers
M.layer = {
	finish = rule(prefixes_global),
}

return M
