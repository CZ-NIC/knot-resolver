-- SPDX-License-Identifier: GPL-3.0-or-later
-- check lua-psl is available
local has_psl = pcall(require, 'psl')
if not has_psl then
	os.exit(77)  -- SKIP policy.slice
end

-- unload modules which are not related to this test
if ta_update then
        modules.unload('ta_update')
end
if ta_signal_query then
        modules.unload('ta_signal_query')
end
if priming then
        modules.unload('priming')
end
if detect_time_skew then
        modules.unload('detect_time_skew')
end

local kres = require('kres')

local slice_queries = {
	{},
	{},
	{},
}

local function sliceaction(index)
	return function(_, req)
		-- log query
		local qry = req:current()
		local name = kres.dname2str(qry:name())
		local count = slice_queries[index][name]
		if not count then
			count = 0
		end
		slice_queries[index][name] = count + 1

		-- refuse query
		local answer = req:ensure_answer()
		if answer == nil then return nil end
		answer:rcode(kres.rcode.REFUSED)
		answer:ad(false)
		return kres.DONE
	end
end

-- configure slicing
policy.add(policy.slice(
	policy.slice_randomize_psl(0),
	sliceaction(1),
	sliceaction(2),
	sliceaction(3)
))

local function check_slice(desc, qname, qtype, expected_slice, expected_count)
	callback = function()
		count = slice_queries[expected_slice][qname]
		qtype_str = kres.tostring.type[qtype]
		same(count, expected_count, desc .. qname .. ' ' .. qtype_str)
	end
	resolve(qname, qtype, kres.class.IN, {}, callback)
end

local function test_randomize_psl()
	local desc = 'randomize_psl() same qname, different qtype (same slice): '
	check_slice(desc, 'example.com.', kres.type.A, 2, 1)
	check_slice(desc, 'example.com.', kres.type.AAAA, 2, 2)
	check_slice(desc, 'example.com.', kres.type.MX, 2, 3)
	check_slice(desc, 'example.com.', kres.type.NS, 2, 4)

	desc = 'randomize_psl() subdomain in same slice: '
	check_slice(desc, 'a.example.com.', kres.type.A, 2, 1)
	check_slice(desc, 'b.example.com.', kres.type.A, 2, 1)
	check_slice(desc, 'c.example.com.', kres.type.A, 2, 1)
	check_slice(desc, 'a.a.example.com.', kres.type.A, 2, 1)
	check_slice(desc, 'a.a.a.example.com.', kres.type.A, 2, 1)

	desc = 'randomize_psl() different qnames in different slices: '
	check_slice(desc, 'example2.com.', kres.type.A, 1, 1)
	check_slice(desc, 'example5.com.', kres.type.A, 3, 1)

	desc = 'randomize_psl() check unregistrable domains: '
	check_slice(desc, '.', kres.type.A, 3, 1)
	check_slice(desc, 'com.', kres.type.A, 1, 1)
	check_slice(desc, 'cz.', kres.type.A, 2, 1)
	check_slice(desc, 'co.uk.', kres.type.A, 1, 1)

	desc = 'randomize_psl() check multi-level reg. domains: '
	check_slice(desc, 'example.co.uk.', kres.type.A, 3, 1)
	check_slice(desc, 'a.example.co.uk.', kres.type.A, 3, 1)
	check_slice(desc, 'b.example.co.uk.', kres.type.MX, 3, 1)
	check_slice(desc, 'example2.co.uk.', kres.type.A, 2, 1)

	desc = 'randomize_psl() reg. domain - always ends up in slice: '
	check_slice(desc, 'fdsnnsdfvkdn.com.', kres.type.A, 3, 1)
	check_slice(desc, 'bdfbd.cz.', kres.type.A, 1, 1)
	check_slice(desc, 'nrojgvn.net.', kres.type.A, 1, 1)
	check_slice(desc, 'jnojtnbv.engineer.', kres.type.A, 2, 1)
	check_slice(desc, 'dfnjonfdsjg.gov.', kres.type.A, 1, 1)
	check_slice(desc, 'okfjnosdfgjn.mil.', kres.type.A, 1, 1)
	check_slice(desc, 'josdhnojn.test.', kres.type.A, 2, 1)
end

return {
	test_randomize_psl,
}
