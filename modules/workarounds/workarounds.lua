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

return M

