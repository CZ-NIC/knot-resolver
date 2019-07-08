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
ev = event.recurrent(1 * sec, function () return 1 end)
event.cancel(ev)
ev = event.after(0, function () return 1 end)


-- Import fake root zone; avoid interference with configured keyfile_default.
trust_anchors.remove('.')
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


local function import_valid_root_zone()
	cache.clear()
	local import_res = cache.zone_import('testroot.zone')
	assert(import_res.code == 0)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() > 0, 'cache is not empty after import of valid signed root zone')
	check_answer('root apex is in cache',
                     '.', kres.type.NS, kres.rcode.NOERROR)
	check_answer('deep subdomain is in cache',
		     'a.b.subtree1.', kres.type.AAAA, kres.rcode.NOERROR)
end

local function import_root_no_soa()
	cache.clear()
	local import_res = cache.zone_import('testroot_no_soa.zone')
	assert(import_res.code == -1)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() == 0 , 'cache is still empty after import of zone without SOA record')
end

local function import_unsigned_root_zone()
	cache.clear()
	local import_res = cache.zone_import('testroot.zone.unsigned')
	assert(import_res.code == 0)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() == 0, 'cache is still empty after import of unsigned zone')
end

local function import_not_root_zone()
	cache.clear()
	local import_res = cache.zone_import('example.com.zone')
	assert(import_res.code == 1)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() == 0, 'cache is still empty after import of other zone than root')
end

local function import_empty_zone()
	cache.clear()
	local import_res = cache.zone_import('empty.zone')
	assert(import_res.code == -1)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() == 0, 'cache is still empty after import of empty zone')
end

local function import_random_trash()
	cache.clear()
	local import_res = cache.zone_import('random.zone')
	assert(import_res.code == -1)
	-- beware that import takes at least 100 ms
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
	-- sanity checks - cache must be filled in
	ok(cache.count() == 0, 'cache is still empty after import of unparseable file')
end

return {
	import_valid_root_zone,
	import_root_no_soa,
	import_unsigned_root_zone,
	import_not_root_zone,
	import_empty_zone,
	import_random_trash,
}
