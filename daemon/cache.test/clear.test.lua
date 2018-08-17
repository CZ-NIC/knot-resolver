-- unload modules which are not related to this test
if ta_signal_query then
        modules.unload('ta_signal_query')
end
if priming then
        modules.unload('priming')
end
if detect_time_skew then
        modules.unload('detect_time_skew')
end

-- test. domain is used by some tests, allow it
policy.add(policy.suffix(policy.PASS, {todname('test.')}))

cache.size = 2*MB
-- verbose(true)

-- Self-checks on globals
assert(help() ~= nil)
assert(worker.id ~= nil)
-- Self-checks on facilities
assert(cache.stats() ~= nil)
assert(cache.backends() ~= nil)
assert(worker.stats() ~= nil)
assert(net.interfaces() ~= nil)
-- Self-checks on loaded stuff
assert(#modules.list() > 0)
-- Self-check timers
ev = event.recurrent(1 * sec, function (ev) return 1 end)
event.cancel(ev)
ev = event.after(0, function (ev) return 1 end)


-- import fake root zone
trust_anchors.add('. IN DS 48409 8 2 3D63A0C25BCE86621DE63636F11B35B908EFE8E9381E0E3E9DEFD89EA952C27D')

local function check_answer(desc, qname, qtype, expected_rcode)
	qtype_str = kres.tostring.type[qtype]
	callback = function(pkt)
		same(pkt:rcode(), expected_rcode,
		     desc .. ': expecting answer for query ' .. qname .. ' ' .. qtype_str
		      .. ' with rcode ' .. kres.tostring.rcode[expected_rcode])

		ok((pkt:ancount() > 0) == (pkt:rcode() == kres.rcode.NOERROR),
		   desc ..': checking number of answers for ' .. qname .. ' ' .. qtype_str)
	end
	resolve(qname, qtype, kres.class.IN, {}, callback)
end

-- do not attempt to contact outside world, operate only on cache
net.ipv4 = false
net.ipv6 = false
-- do not listen, test is driven by config code
env.KRESD_NO_LISTEN = true


local function import_zone()
	local import_res = cache.zone_import('testroot.zone')
	assert(import_res.code == 0)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() > 0, 'cache is not empty after import')
	check_answer('root apex is cache',
	  	     '.', kres.type.NS, kres.rcode.NOERROR)
	check_answer('deep subdomain is in cache',
		     'a.b.subtree1.', kres.type.AAAA, kres.rcode.NOERROR)

end

local function test_exact_match_qtype()
	nok(cache.clear('a.b.subtree1.', true, kres.type.A)['chunk_limit'],
	     'single qname+qtype can be cleared at once')
	check_answer('exact match on qname+qtype must flush RR from cache',
		     'a.b.subtree1.', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('exact match on qname+qtype must not affect other RRs on the same node',
		     'a.b.subtree1.', kres.type.AAAA, kres.rcode.NOERROR)
	check_answer('exact match on qname must not affect parent',
		     'b.subtree1.', kres.type.A, kres.rcode.NOERROR)
end

local function test_exact_match_qname()
	res = cache.clear('a.b.subtree1.')
	is(res.count, 2, 'single qname can be cleared at once')
	check_answer('exact match on qname must flush all RRs with the same owner from cache',
		     'a.b.subtree1.', kres.type.AAAA, kres.rcode.SERVFAIL)
	check_answer('exact match on qname must flush all RRs with the same owner from cache',
		     'a.b.subtree1.', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('exact match on qname must flush all RRs with the same owner from cache',
		     'a.b.subtree1.', kres.type.TXT, kres.rcode.SERVFAIL)
	-- exact match for negative proofs is not implemented yet
	--check_answer('exact match on qname must flush negative proofs for owner from cache',
	--	     'a.b.subtree1.', kres.type.NULL, kres.rcode.SERVFAIL)
	--check_answer('exact match on qname must not affect parent',
	--	     'b.subtree1.', kres.type.A, kres.rcode.NOERROR)
	-- same(cache.clear(), 0, 'full cache clear can be performed')
	--check_answer('.', kres.type.NS, false)

end

local function test_subtree()
	res = cache.clear('subtree1.')
	nok(res.chunk_limit,
	    'whole positive subtree must be flushed (does not include neg. proofs)')
	ok(res.not_apex,
	    'subtree clear below apex must be detected')
        same(res.subtree, '.', 'detected apex must be returned')
	check_answer('subtree variant must flush all RRs in subdomains from cache',
		     'b.subtree1.', kres.type.A, kres.rcode.SERVFAIL)
	check_answer('subtree variant must flush all RRs in subdomains from cache',
		     'b.subtree1.', kres.type.TXT, kres.rcode.SERVFAIL)
	check_answer('subtree variant must flush all RRs in subdomains from cache',
		     'subtree1.', kres.type.TXT, kres.rcode.SERVFAIL)
	check_answer('subtree variant must not affect parent',
		     '.', kres.type.NS, kres.rcode.NOERROR)
	-- same(cache.clear(), 0, 'full cache clear can be performed')
	--check_answer('.', kres.type.NS, false)

end

local function test_callback()
	local test_name = '20r.subtree2.'
	local test_maxcount = 1
	local test_exactname = true
	local test_rrtype = nil
	local test_maxcount = 1
	local test_prev_state = { works = true }
	local function check_callback(name, exact_name, rr_type, chunk_size, callback, prev_state, errors)
		is(errors.count, 1, 'callback received correct # of removed records')
		is(test_name, name, 'callback received subtree name')
		is(test_exactname, exact_name, 'callback received exact_name')
		is(test_rrtype, rrtype, 'callback received rr_type')
		is(test_chunksize, chunksize, 'callback received maxcount')
		is(check_callback, callback, 'callback received reference to itself')
		is(type(errors), 'table', 'callback received table of errors')
		same(test_prev_state, prev_state, 'callback received previous state')
		return 666
	end
	same(cache.clear(test_name, test_exactname, test_rrtype, test_maxcount, check_callback, test_prev_state),
	     666, 'first callback return value is passed to cache.clear() caller')
	local cnt_before_wait = cache.count()
	worker.sleep(0.2)
	is(cnt_before_wait, cache.count(), 'custom callback can stop clearing')
end

local function test_subtree_limit()  -- default limit = 100
	res = cache.clear('subtree2.', false, nil)
	ok(res.chunk_limit,
	   'chunk_size limit must be respected')
	is(res.count, 100,
	   'chunk_size limit must match returned count')

	-- callbacks are running in background so we can now wait
	-- and later verify that everything was removed
	-- 200 RRs, 100 was removed in first call
	-- so the rest should be removed in single invocation of callback
	-- hopefully the machine is not too slow ...
	worker.sleep(0.1)
	res = cache.clear('subtree2.', false, nil)
	is(res.count, 0,
	   'previous calls + callbacks must have removed everything')
end

local function test_apex()
	check_answer('a negative proof is still present in cache',
		     'aaaaa.b.subtree1.', kres.type.TXT, kres.rcode.NXDOMAIN)

	local prev_count = cache.count()
	print(prev_count)
	ok(prev_count > 0, 'previous subtree clearing did not remove everything')
	res = cache.clear('.', false, nil, 10000)
	print(table_print(res))
	is(res.count, prev_count, 'clear on root removed everyting including proofs')
	check_answer('exact match on qname must flush negative proofs for owner from cache',
		     'a.b.subtree1.', kres.type.NULL, kres.rcode.SERVFAIL)
end

local function test_complete_flush()
	local prev_count = cache.count()
	res = cache.clear()
	is(res.count, prev_count, 'full clear reports correct number of entries')
	is(cache.count(), 0, 'cache is empty after full clear')
end

return {
	import_zone,
	test_exact_match_qtype,
	test_exact_match_qname,
	test_callback,
	import_zone,
	test_subtree,
	test_subtree_limit,
	test_apex,
	import_zone,
	test_complete_flush,
}
