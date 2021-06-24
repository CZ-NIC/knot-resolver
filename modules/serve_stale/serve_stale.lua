-- SPDX-License-Identifier: GPL-3.0-or-later
local M = {} -- the module

local ffi = require('ffi')

-- Beware that the timeout is only considered at certain points in time;
-- approximately at multiples of KR_CONN_RTT_MAX.
M.timeout = 3*sec

M.callback = ffi.cast("kr_stale_cb",
	function (ttl) --, name, type, qry)
		--log_debug(ffi.C.SRVSTALE, '   => called back with TTL: ' .. tostring(ttl))
		if ttl + 3600 * 24 > 0 then -- at most one day stale
			return 1
		else
			return -1
		end
	end)

M.layer = {
	produce = function (state, req)
		local qry = req:current()
		-- Don't do anything for priming, prefetching, etc.
		-- TODO: not all cases detected ATM.
		if qry.flags.NO_CACHE then return state end

		local now = ffi.C.kr_now()
		local deadline = qry.creation_time_mono + M.timeout
		if now > deadline or qry.flags.NO_NS_FOUND then
			log_info(ffi.C.LOG_GRP_SRVSTALE, '   => no reachable NS, using stale data')
			qry.stale_cb = M.callback
			-- TODO: probably start the same request that doesn't stale-serve,
			-- but first we need some detection of non-interactive / internal requests.
			-- resolve(kres.dname2str(qry.sname), qry.stype, qry.sclass)
		end

		return state
	end,
}

return M

