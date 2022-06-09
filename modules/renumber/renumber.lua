-- SPDX-License-Identifier: GPL-3.0-or-later
-- Module interface
local ffi = require('ffi')
local prefixes_global = {}

-- get address from config: either subnet prefix or fixed endpoint
local function extract_address(target)
	local idx = string.find(target, "!", 1, true)
	if idx == nil then
		return target, false
	end
	if idx ~= #target then
		error("[renumber] \"!\" symbol in target is only accepted at the end of address")
	end
	return string.sub(target, 1, idx - 1), true
end

-- Create bitmask from integer mask for single octet: 2 -> 11000000
local function getOctetBitmask(intMask)
	return bit.lshift(bit.rshift(255, 8 - intMask), 8 - intMask)
end

-- Merge ipNet with ipHost, using intMask
local function mergeIps(ipNet, ipHost, intMask)
	local octetMask
	local result = ""

	if (#ipNet ~= #ipHost) then
		return nil
	end

	for currentOctetNo = 1, #ipNet do
		if intMask >= 8 then
			result = result .. ipNet:sub(currentOctetNo,currentOctetNo)
		elseif (intMask <= 0) then
			result = result .. ipHost:sub(currentOctetNo,currentOctetNo)
		else
			octetMask = getOctetBitmask(intMask)
			result = result .. string.char(bit.bor(
					bit.band(string.byte(ipNet:sub(currentOctetNo,currentOctetNo)), octetMask),
					bit.band(string.byte(ipHost:sub(currentOctetNo,currentOctetNo)), bit.bnot(octetMask))
			))
		end
		intMask = intMask - 8
	end

	return result
end

-- Create subnet prefix rule
local function matchprefix(subnet, addr)
	local is_exact
	addr, is_exact = extract_address(addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	local subnet_cd = ffi.new('char[16]')
	local bitlen = ffi.C.kr_straddr_subnet(subnet_cd, subnet)
	if bitlen < 0 then error('[renumber] invalid subnet: '..subnet) end
	return {subnet_cd, bitlen, target, addrtype, is_exact}
end

-- Create name match rule
local function matchname(name, addr)
	local is_exact
	addr, is_exact = extract_address(addr) -- though matchname() always leads to replacing whole address
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local owner = todname(name)
	if not name then error('[renumber] invalid name: '..name) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	return {owner, nil, target, addrtype, is_exact}
end

-- Add subnet prefix rewrite rule
local function add_prefix(subnet, addr)
	local prefix = matchprefix(subnet, addr)
	table.insert(prefixes_global, prefix)
end

-- Match IP against given subnet or record owner
local function match_subnet(subnet, bitlen, addrtype, rr)
	local addr = rr.rdata
	return addrtype == rr.type and
	       ((bitlen and (#addr >= bitlen / 8) and (ffi.C.kr_bitcmp(subnet, addr, bitlen) == 0)) or subnet == rr.owner)
end

-- Renumber address record
local function renumber_record(tbl, rr)
	for i = 1, #tbl do
		local prefix = tbl[i]
		local subnet = prefix[1]
		local bitlen = prefix[2]
		local target = prefix[3]
		local addrtype = prefix[4]
		local is_exact = prefix[5]

		-- Match record type to address family and record address to given subnet
		-- If provided, compare record owner to prefix name
		if match_subnet(subnet, bitlen, addrtype, rr) then
			if is_exact then
				rr.rdata = target
			else
				local mergedHost = mergeIps(target, rr.rdata, bitlen)
				if mergedHost ~= nil then rr.rdata = mergedHost end
			end

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
