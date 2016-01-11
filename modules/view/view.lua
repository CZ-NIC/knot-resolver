local kres = require('kres')
local policy = require('policy')
local ffi = require('ffi')
local C = ffi.C

-- Module declaration
local view = {
	key = {},
	subnet = {},
}

-- @function View based on TSIG key name.
function view.tsig(view, tsig, policy)
	view.key[tsig] = policy
end

-- @function View based on source IP subnet.
function view.addr(view, subnet, policy)
	local subnet_cd = ffi.new('char[16]')
	local family = C.kr_straddr_family(subnet)
	local bitlen = C.kr_straddr_subnet(subnet_cd, subnet)
	table.insert(view.subnet, {family, subnet_cd, bitlen, policy})
end

-- @function Match IP against given subnet
local function match_subnet(family, subnet, bitlen, addr)
	return (family == addr:family()) and (C.kr_bitcmp(subnet, addr:ip(), bitlen) == 0)
end

-- @function Find view for given request
local function evaluate(view, req)
	local answer = req.answer
	local client_key = req.qsource.key
	local match_cb = (client_key ~= nil) and view.key[client_key:owner()] or nil
	-- Search subnets otherwise
	if match_cb == nil and req.qsource.addr ~= nil then
		for i = 1, #view.subnet do
			local pair = view.subnet[i]
			if match_subnet(pair[1], pair[2], pair[3], req.qsource.addr) then
				match_cb = pair[4]
				break
			end
		end
	end
	return match_cb
end

-- @function Module layers
view.layer = {
	begin = function(state, req)
		if state == kres.FAIL then return state end
		req = kres.request_t(req)
		local match_cb = evaluate(view, req)
		if match_cb ~= nil then
			local action = match_cb(req, req:current())
			return policy.enforce(state, req, action)
		end
		return state
	end
}

return view
