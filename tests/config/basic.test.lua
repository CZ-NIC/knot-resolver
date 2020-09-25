-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

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
	same(kres.tostring.type[65535], 'TYPE65535', 'text record type undefined constants work')
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
	local rr = {owner = '\3com\0', ttl = 1, type = kres.type.TXT, rdata = '\5hello'}
	local rr_text = tostring(kres.rr2str(rr))
	same(rr_text:gsub('%s+', ' '), 'com. 1 TXT "hello"', 'rrset to text works')
	same(kres.dname2str(todname('com.')), 'com.', 'domain name conversion works')
	-- test creating rrset
	rr = kres.rrset(todname('com.'), kres.type.A, kres.class.IN, 66)
	ok(ffi.istype(kres.rrset, rr), 'created an empty RR')
	same(rr:owner(), '\3com\0', 'created RR has correct owner')
	same(rr:class(), kres.class.IN, 'created RR has correct class')
	same(rr:class(kres.class.CH), kres.class.CH, 'can set a different class')
	same(rr:class(kres.class.IN), kres.class.IN, 'can restore a class')
	same(rr.type, kres.type.A, 'created RR has correct type')
	-- test adding rdata
	same(rr:wire_size(), 0, 'empty RR wire size is zero')
	ok(rr:add_rdata('\1\2\3\4', 4), 'adding RDATA works')
	same(rr:wire_size(), 5 + 4 + 4 + 2 + 4, 'RR wire size works after adding RDATA')
	-- test conversion to text
	local expect = 'com.                	66	A	1.2.3.4\n'
	same(rr:txt_dump(), expect, 'RR to text works')
	-- create a dummy rrsig
	local rrsig = kres.rrset(todname('com.'), kres.type.RRSIG, kres.class.IN, 0)
	rrsig:add_rdata('\0\1', 2)
	same(rr:rdcount(), 1, 'add_rdata really added RDATA')
	-- check rrsig matching
	same(rr.type, rrsig:type_covered(), 'rrsig type covered matches covered RR type')
	ok(rr:is_covered_by(rrsig), 'rrsig is covering a record')
	-- test rrset merging
	local copy = kres.rrset(rr:owner(), rr.type, kres.class.IN, 66)
	ok(copy:add_rdata('\4\3\2\1', 4), 'adding second RDATA works')
	ok(rr:merge_rdata(copy), 'merge_rdata works')
	same(rr:rdcount(), 2, 'RDATA count is correct after merge_rdata')
	expect = 'com.                	66	A	1.2.3.4\n' ..
	         'com.                	66	A	4.3.2.1\n'
	same(rr:txt_dump(), expect, 'merge_rdata actually merged RDATA')
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
	local res, err = pkt:put(nil, 0, 0, 0, '')
	isnt(res, true, 'inserting nil entry doesnt work')
	isnt(err.code, 0, 'error code is non-zero')
	isnt(tostring(res), '', 'inserting nil returns invalid parameter')
	ok(pkt:put(pkt:qname(), 900, pkt:qclass(), kres.type.A, '\1\2\3\4'), 'adding rrsets works')
	boom(pkt.begin, {pkt, 10}, 'switching to invalid section doesnt work')
	ok(pkt:begin(kres.section.ADDITIONAL), 'switching to different section works')
	boom(pkt.begin, {pkt, 0}, 'rewinding sections doesnt work')
	local before_insert = pkt:remaining_bytes()
	ok(pkt:put(pkt:qname(), 900, pkt:qclass(), kres.type.A, '\4\3\2\1'), 'adding rrsets to different section works')
	same(pkt:remaining_bytes(), before_insert - (2 + 4 + 4 + 2 + 4), 'remaining bytes count goes down with insertions')
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
	same(parsed:opcode(), pkt:opcode(), 'parsed packet has same opcode')
	same(parsed:rcode(), pkt:rcode(), 'parsed packet has same rcode')
	same(parsed:rd(), pkt:rd(), 'parsed packet has same RD')
	same(parsed:id(), pkt:id(), 'parsed packet has same MSGID')
	same(parsed:qdcount(), pkt:qdcount(), 'parsed packet has same question count')
	same(parsed:ancount(), pkt:ancount(), 'parsed packet has same answer count')
	same(parsed:nscount(), pkt:nscount(), 'parsed packet has same authority count')
	same(parsed:arcount(), pkt:arcount(), 'parsed packet has same additional count')
	same(parsed:tostring(), pkt:tostring(), 'parsed packet is equal to source packet')

	-- Test adding RR sets directly
	local copy = kres.packet(512)
	copy:question(todname('hello'), kres.class.IN, kres.type.A)
	copy:begin(kres.section.ANSWER)
	local rr = kres.rrset(pkt:qname(), kres.type.A, kres.class.IN, 66)
	rr:add_rdata('\4\3\2\1', 4)
	ok(copy:put_rr(rr), 'adding RR sets directly works')
	ok(copy:recycle(), 'recycling packet works')

	-- Test recycling of packets
	-- Clear_payload keeps header + question intact
	local cleared = kres.packet(#wire, wire) -- same as "parsed" above
	ok(cleared:parse(), 'parsing packet from wire works')
	ok(cleared:clear_payload(), 'clear_payload works')
	same(cleared:id(), pkt:id(), 'cleared packet has same MSGID')
	same(cleared:qr(), pkt:qr(), 'cleared packet has same QR')
	same(cleared:opcode(), pkt:opcode(), 'cleared packet has same OPCODE')
	same(cleared:aa(), pkt:aa(), 'cleared packet has same AA')
	same(cleared:tc(), pkt:tc(), 'cleared packet has same TC')
	same(cleared:rd(), pkt:rd(), 'cleared packet has same RD')
	same(cleared:ra(), pkt:ra(), 'cleared packet has same RA')
	same(cleared:ad(), pkt:ad(), 'cleared packet has same AD')
	same(cleared:cd(), pkt:cd(), 'cleared packet has same CD')
	same(cleared:rcode(), pkt:rcode(), 'cleared packet has same RCODE')
	same(cleared:qdcount(), pkt:qdcount(), 'cleared packet has same question count')
	same(cleared:ancount(), 0, 'cleared packet has no answers')
	same(cleared:nscount(), 0, 'cleared packet has no authority')
	same(cleared:arcount(), 0, 'cleared packet has no additional')
	same(cleared:qname(), pkt:qname(), 'cleared packet has same QNAME')
	same(cleared:qtype(), pkt:qtype(), 'cleared packet has same QTYPE')
	same(cleared:qclass(), pkt:qclass(), 'cleared packet has same QCLASS')

	-- Recycle clears question as well
	ok(pkt:recycle(), 'recycle() works')
	is(pkt:ancount(), 0, 'recycle() clears records')
	is(pkt:qname(), nil, 'recycle() clears question')
	is(#pkt:towire(), 12, 'recycle() clears the packet wireformat')
end

-- test JSON encode/decode functions
local function test_json_functions()
	for msg, obj in pairs({
			['number'] = 0,
			['string'] = 'ok',
			['list'] = {1, 2, 3},
			['map'] = {foo='bar'},
			['nest structure'] = {foo='bar', baz={1,2,3}},
	}) do
		same(fromjson(tojson(obj)), obj, 'json test: ' .. msg)
	end

	for _, str in ipairs({
			'{', '}',
			'[', ']',
			'x,',
			'[1,2,3,]',
	}) do
		boom(fromjson, {'{'}, 'json test: invalid \'' .. str .. '\'')
	end
end

return {
	test_constants,
	test_globals,
	test_rrset_functions,
	test_packet_functions,
	test_json_functions,
}
