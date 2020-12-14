-- SPDX-License-Identifier: GPL-3.0-or-later
local kres = require('kres')
local ffi = require('ffi')
local C = ffi.C

-- Module declaration
local view = {
	key = {}, -- map from :owner() to list of policy rules
	src = {},
	dst = {},
}

-- @function View based on TSIG key name.
function view.tsig(_, tsig, rule)
	if view.key[tsig] == nil then
		view.key[tsig] = { rule }
	else
		table.insert(view.key[tsig], rule)
	end
end

-- @function View based on source IP subnet.
function view.addr(_, subnet, rules, dst)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	if bitlen < 0 then
		error(string.format('failed to parse subnet %s', subnet))
	end
	local t = {family, subnet_cd, bitlen, rules}
	table.insert(dst and view.dst or view.src, t)
	return t
end

-- @function Match IP against given subnet
local function match_subnet(family, subnet, bitlen, addr)
	return (family == addr:family()) and (C.kr_bitcmp(subnet, addr:ip(), bitlen) == 0)
end

-- @function Execute a policy callback (may be nil);
-- return boolean: whether to continue trying further rules.
local function execute(state, req, match_cb)
	if match_cb == nil then return false end
	local action = match_cb(req, req:current())
	if action == nil then return false end
	local next_state = action(state, req)
	if next_state then    -- Not a chain rule,
		req.state = next_state
		return true
	else
		return false
	end
end

-- @function Try all the rules in order, until a non-chain rule gets executed.
local function evaluate(state, req)
	-- Try :tsig rules first.
	local client_key = req.qsource.packet.tsig_rr
	local match_cbs = (client_key ~= nil) and view.key[client_key:owner()] or {}
	for _, match_cb in ipairs(match_cbs) do
		if execute(state, req, match_cb) then return end
	end
	-- Then try :addr by the source.
	if req.qsource.addr ~= nil then
		for i = 1, #view.src do
			local pair = view.src[i]
			if match_subnet(pair[1], pair[2], pair[3], req.qsource.addr) then
				local match_cb = pair[4]
				if execute(state, req, match_cb) then return end
			end
		end
	-- Finally try :addr by the destination.
	elseif req.qsource.dst_addr ~= nil then
		for i = 1, #view.dst do
			local pair = view.dst[i]
			if match_subnet(pair[1], pair[2], pair[3], req.qsource.dst_addr) then
				local match_cb = pair[4]
				if execute(state, req, match_cb) then return end
			end
		end
	end
end

-- @function Return policy based on source address
function view.rule_src(action, subnet)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	return function(req, _)
		local addr = req.qsource.addr
		if addr ~= nil and match_subnet(family, subnet_cd, bitlen, addr) then
			return action
		end
	end
end

-- @function Return policy based on destination address
function view.rule_dst(action, subnet)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	return function(req, _)
		local addr = req.qsource.dst_addr
		if addr ~= nil and match_subnet(family, subnet_cd, bitlen, addr) then
			return action
		end
	end
end

-- @function Module layers
view.layer = {
	begin = function(state, req)
		-- Don't act on "finished" cases.
		if bit.band(state, bit.bor(kres.FAIL, kres.DONE)) ~= 0 then return state end

		evaluate(state, req)
		return req.state
	end
}

return view
