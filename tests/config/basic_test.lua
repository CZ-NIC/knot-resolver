-- test if constants work properly
local function test_constants()
	same(kres.class.IN, 1, 'class constants work')
	same(kres.type.NS, 2, 'record type constants work')
	same(kres.type.TYPE2, 2, 'unnamed record type constants work')
	same(kres.type.BADTYPE, nil, 'non-existent type constants are checked')
	same(kres.rcode.SERVFAIL, 2, 'rcode constants work')
end

-- test globals
local function test_globals()
	ok(mode('strict'), 'changing strictness mode')
	boom(mode, {'badmode'}, 'changing to non-existent strictness mode')
	same(reorder_RR(true), true, 'answer section reordering')
	same(option('REORDER_RR', false), false, 'generic option call')
	boom(option, {'REORDER_RR', 'potato'}, 'generic option call argument check')
	boom(option, {'MARS_VACATION', false}, 'generic option check name')
	same(table_print('crabdiary'), 'crabdiary\n', 'table print works')
	same(table_print({fakepizza=1}), '[fakepizza] => 1\n', 'table print works on tables')
end

-- test if dns library functions work
local function test_kres_functions()
	local rr = {owner = '\3com', ttl = 1, type = kres.type.TXT, rdata = '\5hello'}
	local rr_text = tostring(kres.rr2str(rr))
	same(rr_text:gsub('%s+', ' '), 'com. 1 TXT "hello"', 'rrset to text works')
	same(kres.dname2str(todname('com.')), 'com.', 'domain name conversion works')
end

return {
	test_constants,
	test_globals,
	test_kres_functions,
}