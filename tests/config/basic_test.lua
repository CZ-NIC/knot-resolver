-- test if constants work properly
local function test_constants()
	same(kres.class.IN, 1, 'class constants work')
	same(kres.type.NS, 2, 'record type constants work')
	same(kres.type.TYPE2, 2, 'unnamed record type constants work')
	same(kres.type.BADTYPE, nil, 'non-existent type constants are checked')
	same(kres.section.ANSWER, 0, 'section constants work')
	same(kres.rcode.SERVFAIL, 2, 'rcode constants work')
	same(kres.opcode.UPDATE, 5, 'opcode constants work')
	-- Test inverset tables to convert constants to text
	same(kres.tostring.class[1], 'IN', 'text class constants work')
	same(kres.tostring.type[2], 'NS', 'text record type constants work')
	same(kres.tostring.section[0], 'ANSWER', 'text section constants work')
	same(kres.tostring.rcode[2], 'SERVFAIL', 'text rcode constants work')
	same(kres.tostring.opcode[5], 'UPDATE', 'text opcode constants work')
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
local function test_rrset_functions()
	local rr = {owner = '\3com', ttl = 1, type = kres.type.TXT, rdata = '\5hello'}
	local rr_text = tostring(kres.rr2str(rr))
	same(rr_text:gsub('%s+', ' '), 'com. 1 TXT "hello"', 'rrset to text works')
	same(kres.dname2str(todname('com.')), 'com.', 'domain name conversion works')
end

-- test dns library packet interface
local function test_packet_functions()
	local pkt = kres.packet(512)
	isnt(pkt, nil, 'creating packets works')
	-- Test manipulating header
	ok(pkt:rcode(kres.rcode.NOERROR), 'setting rcode works')
	same(pkt:rcode(), 0, 'getting rcode works')
	same(pkt:opcode(), 0, 'getting opcode works')
	is(pkt:aa(), false, 'packet is created without AA')
	is(pkt:ra(), false, 'packet is created without RA')
	is(pkt:ad(), false, 'packet is created without AD')
	ok(pkt:rd(true), 'setting RD bit works')
	is(pkt:rd(), true, 'getting RD bit works')
	ok(pkt:tc(true), 'setting TC bit works')
	is(pkt:tc(), true, 'getting TC bit works')
	ok(pkt:tc(false), 'disabling TC bit works')
	is(pkt:tc(), false, 'getting TC bit after disable works')
	is(pkt:cd(), false, 'getting CD bit works')
	is(pkt:id(1234), 1234, 'setting MSGID works')
	is(pkt:id(), 1234, 'getting MSGID works')
	-- Test manipulating question
	is(pkt:qname(), nil, 'reading name from empty question')
	is(pkt:qtype(), 0, 'reading type from empty question')
	is(pkt:qclass(), 0, 'reading class from empty question')
	ok(pkt:question(todname('hello'), kres.class.IN, kres.type.A), 'setting question section works')
	same(pkt:qname(), todname('hello'), 'reading QNAME works')
	same(pkt:qtype(), kres.type.A, 'reading QTYPE works')
	same(pkt:qclass(), kres.class.IN, 'reading QCLASS works')
	-- Test manipulating sections
	ok(pkt:begin(kres.section.ANSWER), 'switching sections works')
	ok(pkt:put(pkt:qname(), 900, pkt:qclass(), kres.type.A, '\1\2\3\4'), 'adding rrsets works')
	boom(pkt.begin, {pkt, 10}, 'switching to invalid section doesnt work')
	ok(pkt:begin(kres.section.ADDITIONAL), 'switching to different section works')
	boom(pkt.begin, {pkt, 0}, 'rewinding sections doesnt work')
	ok(pkt:put(pkt:qname(), 900, pkt:qclass(), kres.type.A, '\4\3\2\1'), 'adding rrsets to different section works')
	-- Test conversions to text
	like(pkt:tostring(), '->>HEADER<<-', 'packet to text works')
	-- Test deserialization
	local wire = pkt:towire()
	same(#wire, 55, 'packet serialization works')
	local parsed = kres.packet(#wire, wire)
	isnt(parsed, nil, 'creating packet from wire works')
	ok(parsed:parse(), 'parsing packet from wire works')
	same(parsed:qname(), pkt:qname(), 'parsed packet has same QNAME')
	same(parsed:qtype(), pkt:qtype(), 'parsed packet has same QTYPE')
	same(parsed:qclass(), pkt:qclass(), 'parsed packet has same QCLASS')
	same(parsed:rcode(), pkt:rcode(), 'parsed packet has same rcode')
	same(parsed:rd(), pkt:rd(), 'parsed packet has same RD')
	same(parsed:id(), pkt:id(), 'parsed packet has same MSGID')
	same(parsed:ancount(), pkt:ancount(), 'parsed packet has same answer count')
	same(parsed:tostring(), pkt:tostring(), 'parsed packet is equal to source packet')
end

return {
	test_constants,
	test_globals,
	test_rrset_functions,
	test_packet_functions,
}