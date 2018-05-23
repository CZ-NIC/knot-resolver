-- test if cache module properties work
local function test_properties()
	is(type(cache), 'table', 'cache module is loaded')
	is(cache.count(), 0, 'cache is empty on startup')
	local backends = cache.backends()
	is(type(backends), 'table', 'cache provides a list of backends')
	ok(backends['lmdb'], 'cache provides built-in lmdb backend')
	is(cache.current_storage, 'lmdb://', 'cache starts with lmdb backend')
	is(cache.current_size, 100 * MB, 'cache starts with default size limit')
	is(cache.max_ttl(10), 10, 'allows setting maximum TTL')
	is(cache.max_ttl(), 10, 'stored maximum TTL')
	is(cache.min_ttl(1), 1, 'allows setting minimum TTL')
	is(cache.min_ttl(), 1, 'stored minimum TTL')
end

-- test if the stats work with reopening the cache
local function test_stats()
	ok(cache.close(), 'cache can be closed')
	boom(cache.open, {100 * MB, 'invalid://'}, 'cache cannot be opened with invalid backend')
	ok(cache.open(100 * MB), 'cache can be reopened')
	local s = cache.stats()
	is(type(s), 'table', 'stats returns a table')
	same({s.hit, s.miss, s.insert, s.delete}, {0, 0, 0, 0}, 'stats returns correct fields')
end

-- test if cache can be resized or shrunk
local function test_resize()
	ok(cache.open(200 * MB, 'lmdb://'), 'cache can be resized')
	is(cache.current_size, 200 * MB, 'cache was resized')
	ok(cache.open(50 * MB), 'cache can be shrunk')
	is(cache.current_size, 50 * MB, 'cache was shrunk')
end

-- test access to cache through context
local function test_context_cache()
	local c = kres.context().cache
	is(type(c), 'cdata', 'context has a cache object')
	local s = c.stats
	same({s.hit, s.miss, s.insert, s.delete}, {0, 0, 0, 0}, 'context cache stats works')
	-- insert a record into cache
	local rdata = '\1\2\3\4'
	local rr = kres.rrset('\3com\0', kres.type.A, kres.class.IN)
	rr:add_rdata(rdata, #rdata, 66)
	ok(c:insert(rr, nil, 0, 0), 'cache insertion works')
	ok(c:sync(), 'cache sync works')
	same(s.insert, 1, 'cache insertion increments counters')
end

-- test cache CRUD operations
local function test_cache_ops()
	local c = kres.context().cache

	local rr = kres.rrset('\3com\0', kres.type.A, kres.class.IN)
	rr:add_rdata('\1\2\3\4', 4, 30)
	ok(c:insert(rr, nil, 0, 0), 'cache insertion works')

	rr = kres.rrset('\3com\0', kres.type.AAAA, kres.class.IN)
	rr:add_rdata('\1', 1, 30)
	ok(c:insert(rr, nil, 0, 0), 'cache insertion works')

	local r = cache.get('com')
	ok(r['com.'] and r['com.'].A and r['com.'].AAAA, 'cache match works')

	local n = cache.clear('com', kres.type.A)
	r = cache.get('com')
	ok(n == 1 and not r['com.'].A, 'cache delete for single rr works')

	local n = cache.clear('com')
	local s, r = pcall(cache.get, 'com')
	ok(n == 1 and not s, 'cache delete for domain prefix works')
end

return {
	test_properties,
	test_stats,
	test_resize,
	test_context_cache,
	test_cache_ops,
}
