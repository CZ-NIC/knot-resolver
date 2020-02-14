-- SPDX-License-Identifier: GPL-3.0-or-later
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

-- test if the stats work with reopening the cache and operations fail with closed cache
local function test_stats()
	ok(cache.close(), 'cache can be closed')
	boom(cache.open, {100 * MB, 'invalid://'}, 'cache cannot be opened with invalid backend')

	boom(cache.clear, {}, '.clear() does not work on closed cache')
	boom(cache.count, {}, '.count() does not work on closed cache')
	boom(cache.get, { 'key' }, '.get(...) does not work on closed cache')

	ok(cache.open(100 * MB), 'cache can be reopened')
	local s = cache.stats()
	is(type(s), 'table', 'stats returns a table')
	-- Just checking the most useful fields
	isnt(s.read and s.read_miss and s.write, nil, 'stats returns correct fields')
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
	isnt(s.read and s.read_miss and s.write, 'context cache stats works')
	-- insert A record into cache
	local rdata = '\1\2\3\4'
	local rr = kres.rrset('\3com\0', kres.type.A, kres.class.IN, 66)
	rr:add_rdata(rdata, #rdata)
	local s_write = s.write
	ok(c:insert(rr, nil, 0, 0), 'cache insertion works (A)')
	ok(c:commit(), 'cache commit works')
	isnt(s.write, s_write, 'cache insertion increments counters')
	-- insert NS record into cache
	local rr_ns = kres.rrset('\3com\0', kres.type.NS, kres.class.IN, 66)
	local rdata_ns = todname('c.gtld-servers.net')
	ok(rr_ns:add_rdata(rdata_ns, #rdata_ns), 'adding rdata works')
	ok(c:insert(rr_ns, nil, 0), 'cache insertion works (NS)')
end

return {
	test_properties,
	test_stats,
	test_resize,
	test_context_cache,
}
