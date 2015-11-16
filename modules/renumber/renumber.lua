-- Module interface
local policy = require('policy')
local ffi = require('ffi')
local bit = require('bit')
local mod = {}
local prefixes = {}
-- Add subnet prefix rewrite rule
local function add_prefix(subnet, addr)
	local target = kres.str2ip(addr)
	if target == nil then error('[renumber] invalid address: '..addr) end
	local subnet_cd = ffi.new('char[16]')
	local family = ffi.C.kr_straddr_family(subnet)
	local bitlen = ffi.C.kr_straddr_subnet(subnet_cd, subnet)
	table.insert(prefixes, {family, subnet_cd, bitlen, target})
end
-- Match IP against given subnet
local function match_subnet(family, subnet, bitlen, addr)
	return (#addr >= bitlen / 8) and (ffi.C.kr_bitcmp(subnet, addr, bitlen) == 0)
end
-- Renumber address record
local function renumber(tbl, rr)
	for i = 1, #tbl do
		local prefix = tbl[i]
		if match_subnet(prefix[1], prefix[2], prefix[3], rr.rdata) then
			local to_copy = prefix[3]
			local chunks = to_copy / 8
			local rdlen = #rr.rdata
			if rdlen < chunks then return rr end -- Address length mismatch
			local rd = ffi.new('char [?]', rdlen, rr.rdata)
			ffi.copy(rd, prefix[4], chunks)
			-- @todo: CIDR not supported
			to_copy = to_copy - chunks * 8
			rr.rdata = ffi.string(rd, rdlen)
			return rr
		end
	end	
	return nil
end
-- Config
function mod.config (conf)
	if conf == nil then return end
	if type(conf) ~= 'table' then error('[renumber] expected { {prefix, target}, ... }') end
	for i = 1, #conf do add_prefix(conf[i][1], conf[1][2]) end
end
-- Layers
mod.layer = {
	finish = function (state, req)
		req = kres.request_t(req)
		pkt = kres.pkt_t(req.answer)
		-- Only successful answers
		local records = pkt:section(kres.section.ANSWER)
		local ancount = #records
		if state ~= kres.DONE or ancount == 0 then
			return state
		end
		-- Find renumber candidates
		local changed = false
		for i = 1, ancount do
			local rr = records[i]
			if rr.type == kres.type.A then
				local new_rr = renumber(prefixes, rr)
				if new_rr ~= nil then
					records[i] = new_rr
					changed = true
				end
			end
		end
		if not changed then return state end
		-- Replace section if renumbering
		local qname = pkt:qname()
		local qclass = pkt:qclass()
		local qtype = pkt:qtype()
		pkt:clear()
		pkt:question(qname, qclass, qtype)
		for i = 1, ancount do
			local rr = records[i]
			-- Strip signatures as rewritten data cannot be validated
			if rr.type ~= kres.type.RRSIG then
				pkt:put(rr.owner, rr.ttl, rr.class, rr.type, rr.rdata)
			end
		end
		return state
	end
}
return mod
