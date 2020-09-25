-- SPDX-License-Identifier: GPL-3.0-or-later
-- Load dependent module
if not policy then modules.load('policy') end

local M = {} -- the module

function M.config()
	policy.add(policy.suffix(policy.FLAGS('NO_0X20'), {
		--  https://github.com/DNS-OARC/dns-violations/blob/master/2017/DVE-2017-0003.md
		todname('avqs.mcafee.com'), todname('avts.mcafee.com'),

		--  https://github.com/DNS-OARC/dns-violations/blob/master/2017/DVE-2017-0006.md
		--  Obtained via a reverse search on {ns1,ns3}.panthercdn.com.
		todname('cdnga.com'), todname('cdngc.com'), todname('cdngd.com'),
		todname('cdngl.com'), todname('cdngm.com'),
		todname('cdngc.net'), todname('panthercdn.com'),

		todname('magazine-fashion.net.'),
	}))
end

-- Issue #139: When asking certain nameservers for PTR, disable 0x20.
-- Just listing the *.in-addr.arpa suffixes would be tedious, as there are many.
M.layer = {
	produce = function (state, req)
		local qry = req:current()
		if qry.stype ~= kres.type.PTR
			or bit.band(state, bit.bor(kres.FAIL, kres.DONE)) ~= 0
			then return state -- quick exit in most cases
		end
		if qry.flags.AWAIT_CUT or qry.ns.name == nil
			then return state end
		local name = kres.dname2str(qry.ns.name)
		if not name then return state end

		-- The problematic nameservers:
		-- (1) rdnsN.turktelekom.com.tr.
		if string.sub(name, 6) == '.turktelekom.com.tr.' then
			qry.flags.NO_0X20 = true
			qry.flags.NO_MINIMIZE = true
			-- ^ NO_MINIMIZE isn't required for success, as kresd will retry
			-- after getting refused, but it will speed things up.

		-- (2)
		elseif name == 'dns1.edatel.net.co.' then
			qry.flags.NO_0X20 = true
		end

		return state
	end,
}

return M

