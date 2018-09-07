-- Module interface
local ffi = require('ffi')

-- Export module interface
local M = {
	prefixes = {},
}

-- Create subnet prefix rule
function M.prefix(subnet, addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	local subnet_cd = ffi.new('char[16]')
	local bitlen = ffi.C.kr_straddr_subnet(subnet_cd, subnet)
	-- Mask unspecified, renumber whole IP
	if bitlen == 0 then
		bitlen = #target * 8
	end
	return {subnet_cd, bitlen, target, addrtype}
end

-- Create name match rule
function M.name(name, addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local owner = todname(name)
	if not name then error('[renumber] invalid name: '..name) end
	local addrtype = string.find(addr, ':', 1, true) and kres.type.AAAA or kres.type.A
	return {owner, nil, target, addrtype}
end

-- Add subnet prefix rewrite rule
local function add_prefix(subnet, addr)
	table.insert(M.prefixes, M.prefix(subnet, addr))
end

-- Match IP against given subnet or record owner
function M.match_subnet(subnet, bitlen, addrtype, rr)
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
		if M.match_subnet(prefix[1], prefix[2], prefix[4], rr) then
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
function M.rule(prefixes)
	return function (state, _, _, pkt)
		if state == kres.FAIL then return state end
		-- Only successful answers
		local records = pkt:section(kres.section.ANSWER)
		-- Find renumber candidates
		local changed = false
		for i, rr in ipairs(records) do
			if rr.type == kres.type.A or rr.type == kres.type.AAAA then
				local new_rr = renumber_record(prefixes, rr)
				if new_rr ~= nil then
					records[i] = new_rr
					changed = true
				end
			end
		end
		-- If not rewritten, chain action
		if not changed then return end
		-- Replace section if renumbering
		pkt:clear_payload()
		for _, rr in ipairs(records) do
			-- Strip signatures as rewritten data cannot be validated
			if rr.type ~= kres.type.RRSIG then
				pkt:put(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
			end
		end
		return state
	end
end

-- Config
function M.config (conf)
	if conf == nil then return end
	if type(conf) ~= 'table' or type(conf[1]) ~= 'table' then
		error('[renumber] expected { {prefix, target}, ... }')
	end
	for i = 1, #conf do add_prefix(conf[i][1], conf[1][2]) end
end

-- Layers
M.layer = {
	finish = M.rule(M.prefixes),
}

return M
