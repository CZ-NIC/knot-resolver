-- SPDX-License-Identifier: GPL-3.0-or-later
-- Speculative prefetching for repetitive and soon-expiring records to reduce latency.
-- @module prefetch
local prefetch = {}


prefetch.layer = {
	-- Prefetch all expiring (sub-)queries immediately after the request finishes.
	-- Doing that immediately is simplest and avoids creating (new) large bursts of activity.
	finish = function (_, req)
		local qrys = req.rplan.resolved
		for i = 0, (tonumber(qrys.len) - 1) do -- size_t doesn't work for some reason
			local qry = qrys.at[i]
			if qry.flags.EXPIRING == true then
				resolve(kres.dname2str(qry.sname), qry.stype, qry.sclass, {'NO_CACHE'})
			end
		end
	end
}

return prefetch
