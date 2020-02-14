-- SPDX-License-Identifier: GPL-3.0-or-later
local condition = require('cqueues.condition')

-- setup resolver
modules = { 'hints', 'dns64' }
hints['dns64.example'] = '192.168.1.1'
hints.use_nodata(true) -- Respond NODATA to AAAA query
hints.ttl(60)
dns64.config('fe80::21b:77ff:0:0')

-- helper to wait for query resolution
local function wait_resolve(qname, qtype)
	local waiting, done, cond = false, false, condition.new()
	local rcode, answers = kres.rcode.SERVFAIL, {}
	resolve {
		name = qname,
		type = qtype,
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

-- test builtin rules
local function test_builtin_rules()
	local rcode, answers = wait_resolve('dns64.example', kres.type.AAAA)
	same(rcode, kres.rcode.NOERROR, 'dns64.example returns NOERROR')
	same(#answers, 1, 'dns64.example synthesised answer')
	local expect = {'dns64.example.', '60', 'AAAA', 'fe80::21b:77ff:c0a8:101'}
	if #answers > 0 then
		local rr = {kres.rr2str(answers[1]):match('(%S+)%s+(%S+)%s+(%S+)%s+(%S+)')}
		same(rr, expect, 'dns64.example synthesised correct AAAA record')
	end
end

-- plan tests
local tests = {
	test_builtin_rules,
}

return tests
