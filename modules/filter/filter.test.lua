-- SPDX-License-Identifier: GPL-3.0-or-later
-- try loading the module
local has_filter = pcall(modules.load, 'filter')
if not has_filter then
	os.exit(77) -- SKIP filter tests
end

local kres = require('kres')
local condition = require('cqueues.condition')

-- helper to wait for query resolution
local function wait_resolve(qname)
	local waiting, done, cond = false, false, condition.new()
	local rcode, answers = kres.rcode.SERVFAIL, {}
	resolve {
		name = qname,
		finish = function (answer, _)
			rcode = answer:rcode()
			answers = answer:section(kres.section.ANSWER)
			-- Signal as completed
			if waiting then
				cond:signal()
			end
			done = true
		end,
	}
	-- Wait if it didn't finish immediately
	if not done then
		waiting = true
		cond:wait()
	end
	return rcode, answers
end

local function test_filtered(domains, retcode, ansval)
        local rcodestr
        if retcode == kres.rcode.NOERROR then
                rcodestr = "NOERROR"
        else
                rcodestr = "NXDOMAIN"
        end

        for i = 1, #domains do
	        local rcode, answers = wait_resolve(domains[i])
	        same(rcode, retcode, domains[i] .. ' returns ' .. rcodestr)
	        same(#answers, ansval, domains[i] .. ' synthesised answer')
	end
end

local function test_central_eu()
        local domains = {
                'nic.cz', 'xn--hkyrky-ptac70bc.cz', 'xn--mbel-5qa.de',
                'xn--mller-kva.de', 'xn--strae-oqa.de', 'xn--lut-noa55d.com'
                -- 'nic.cz', 'háčkyčárky.cz', 'möbel.de',
                -- 'müller.de', 'straße.de', 'žlutý.com',
        }

        test_filtered(domains, kres.rcode.NOERROR, 1)
end

local function test_forbidden()
        local domains = {
                'xn--mgberp4a5d4ar.com', 'xn--h1alffa9f.xn--p1ai', 'xn--11bd3b0bc5g3dta.test',
                'xn--io0a7i.xn--fiqs8s', 'xn--trke-2oa7j.com', '\x82.com'
                -- 'السعودية.com', 'россия.рф', ' योगात्मक.test',
                -- '网络.中国', 'türkçe.com', '\\\x82.com'
        }

        test_filtered(domains, kres.rcode.NXDOMAIN, 0)
end

return {
        test_central_eu,
        test_forbidden,
}
