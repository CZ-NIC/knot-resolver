local ffi = require('ffi')
local C = ffi.C
local condition = require('cqueues.condition')

-- setup resolver
modules = { 'policy', 'extended_dns_error' }

local ntohs = function(x)
	if not ffi.abi('le') then
		return x
	end
	return bit.rshift(bit.bswap(x), 16)
end

-- helper to wait for query resolution
local function append_ede(code)
	local desc = policy.add(
		policy.all(
			function(_, req, query, pkt, _, _)
				query.err = code
				req:vars().request_doh_host = 'test'
				pkt:rcode(kres.rcode.SERVFAIL)
				return kres.FAIL
	end))


	local waiting, done, cond = false, false, condition.new()
	local ede = 0
	resolve {
		name = 'ede.test',
		type = kres.type.A,
		finish = function (answer, _)
			local opt = C.knot_edns_get_option(answer.opt_rr, 0xFEDE)
			if opt == nil then
				done = true
				return
			end
			opt = ffi.cast('uint16_t *', opt)
			-- skip optcode and len
			-- FIXME: knot_edns_opt_get_data will hang here
			-- payload = C.knot_edns_opt_get_data(opt)
			payload = ffi.cast('struct ede_payload *', opt + 2)
			ede = ntohs(payload.icode)
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

	policy.del(desc.id)

	return ede
end

-- test builtin rules
local function test_ede()
	local ede = append_ede(1001)
	same(1001, ede)
end

-- plan tests
local tests = {
	test_ede,
}

return tests
