-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

-- Protection from DNS rebinding attacks
local kres = require('kres')
local renumber = require('kres_modules.renumber')
local policy = require('kres_modules.policy')

local WhiteListEntry = {}
WhiteListEntry.__index = WhiteListEntry

setmetatable(WhiteListEntry, {
	__call = function(cls, ...)
		return cls:new(...)
	end
})

local function add_subnet(rr_list, subnet)
	local addr = string.find(subnet, ':', 1, true) and '::' or '0.0.0.0'
	table.insert(rr_list, renumber.prefix(subnet, addr))
end

function WhiteListEntry:new(str_dname, ...)
	local rr_list = {}
	for _, v in ipairs({...}) do
		add_subnet(rr_list, v)
	end

	-- normalize domain name (add '.') at end, as that is what incoming queries have
	if str_dname[#str_dname] ~= '.' then
		str_dname = str_dname .. '.'
	end
	local dname = kres.str2dname(str_dname)

	return setmetatable({dname = dname, rr_list = rr_list}, self);
end

local function is_rr_match(rr_list, rr)
	for i = 1, #rr_list do
		local prefix = rr_list[i]
		-- Match record type to address family and record address to given subnet
		if renumber.match_subnet(prefix[1], prefix[2], prefix[4], rr) then
			return true
		end
	end
	return false
end

function WhiteListEntry:match(rr)
	local dname = self.dname
	if not string.find(rr.owner, dname, -string.len(dname), true) then
		return false
	end
	log_info(ffi.C.LOG_GRP_REBIND, 'checking whitelist match for %s', kres.rr2str(rr))
	return is_rr_match(self.rr_list, rr)
end

local M = {}
M.layer = {}
M.blacklist = {
	-- https://www.iana.org/assignments/iana-ipv4-special-registry
	-- + IPv4-to-IPv6 mapping
	renumber.prefix('0.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:0.0.0.0/104', '::'),
	renumber.prefix('10.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:10.0.0.0/104', '::'),
	renumber.prefix('100.64.0.0/10', '0.0.0.0'),
	renumber.prefix('::ffff:100.64.0.0/106', '::'),
	renumber.prefix('127.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:127.0.0.0/104', '::'),
	renumber.prefix('169.254.0.0/16', '0.0.0.0'),
	renumber.prefix('::ffff:169.254.0.0/112', '::'),
	renumber.prefix('172.16.0.0/12', '0.0.0.0'),
	renumber.prefix('::ffff:172.16.0.0/108', '::'),
	renumber.prefix('192.168.0.0/16', '0.0.0.0'),
	renumber.prefix('::ffff:192.168.0.0/112', '::'),
	-- https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	renumber.prefix('::/128', '::'),
	renumber.prefix('::1/128', '::'),
	renumber.prefix('fc00::/7', '::'),
	renumber.prefix('fe80::/10', '::'),
} -- second parameter for renumber module is ignored except for being v4 or v6
M.whitelist = {}

function M.add_whitelist_entry(str_dname, ...)
	table.insert(M.whitelist, WhiteListEntry(str_dname, ...))
end

local function is_rr_blacklisted(rr)
	if is_rr_match(M.blacklist, rr) then
		local whitelist = M.whitelist
		for i = 1, #whitelist do
			if whitelist[i]:match(rr) then
				return false
			end
		end
		return true
	end
	return false
end

local function check_section(pkt, section)
	local records = pkt:section(section)
	local count = #records
	if count == 0 then
		return nil end
	for i = 1, count do
		local rr = records[i]
		if rr.type == kres.type.A or rr.type == kres.type.AAAA then
			local result = is_rr_blacklisted(rr)
			if result then
				return rr end
		end
	end
end

local function check_pkt(pkt)
	for _, section in ipairs({kres.section.ANSWER,
				  kres.section.AUTHORITY,
				  kres.section.ADDITIONAL}) do
		local bad_rr = check_section(pkt, section)
		if bad_rr then
			return bad_rr
		end
	end
end

local function refuse(req)
	policy.REFUSE(nil, req)
	local pkt = req:ensure_answer()
	if pkt == nil then return nil end
	pkt:aa(false)
	pkt:begin(kres.section.ADDITIONAL)

	local msg = 'blocked by DNS rebinding protection'
	pkt:put('\11explanation\7invalid\0', 10800, pkt:qclass(), kres.type.TXT,
			string.char(#msg) .. msg)
	return kres.DONE
end

-- act on DNS queries which were not answered from cache
function M.layer.consume(state, req, pkt)
	if state == kres.FAIL then
		return state end

	local qry = req:current()
	if qry.flags.CACHED or qry.flags.ALLOW_LOCAL then  -- do not slow down cached queries
		return state end

	local bad_rr = check_pkt(pkt)
	if not bad_rr then
		return state end

	qry.flags.RESOLVED = 1  -- stop iteration
	qry.flags.CACHED = 1  -- do not cache

	--[[ In case we're in a sub-query, we do not touch the final req answer.
		Only this sub-query will get finished without a result - there we
		rely on the iterator reacting to flags.RESOLVED
		Typical example: NS address resolution -> only this NS won't be used
		but others may still be OK (or we SERVFAIL due to no NS being usable).
	--]]
	if qry.parent == nil then
		state = refuse(req)
	end
	log_qry(qry, ffi.C.LOG_GRP_REBIND,
		'blocking blacklisted IP in RR \'%s\'\n', kres.rr2str(bad_rr))
	return state
end

return M
