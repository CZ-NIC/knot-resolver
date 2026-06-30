-- SPDX-License-Identifier: GPL-3.0-or-later
local condition = require('cqueues.condition')

-- setup resolver
modules = { 'dns64' }
dns64.config('fe80::21b:77ff:0:0')

local ffi = require('ffi')
local C = ffi.C
-- this is a bit hacky, basically copy&paste from Lua converted from YAML
-- kresctl convert t/conf/tmp.yaml --type policy-loader
rrs = ffi.new('struct kr_rule_zonefile_config')
rrs.ttl = 60
rrs.nodata = true
rrs.is_rpz = false
rrs.input_str = [[
dns64.example.  A  192.168.1.1
dns64-cname.example.  CNAME  dns64.example.
]]
rrs.opts = C.KR_RULE_OPTS_DEFAULT
assert(C.kr_rule_zonefile(rrs)==0)


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
	local names = {"dns64.example", "dns64-cname.example"}
	for i, name in ipairs(names) do
		local rcode, answers = wait_resolve(name, kres.type.AAAA)
		same(rcode, kres.rcode.NOERROR, name .. ' returns NOERROR')
		-- Note hacky: the count `i` and the constant 'dns64.example.' here.
		same(#answers, i, name .. ' synthesised answer')
		local expect = {'dns64.example.', '60', 'AAAA', 'fe80::21b:77ff:c0a8:101'}
		if #answers > 0 then
			local rr = {kres.rr2str(answers[#answers]):match('(%S+)%s+(%S+)%s+(%S+)%s+(%S+)')}
			same(rr, expect, name .. ' synthesised correct AAAA record')
		end
	end
end

-- plan tests
local tests = {
	test_builtin_rules,
}

return tests
