local ffi = require('ffi')
local condition = require('cqueues.condition')

-- setup resolver
modules = { 'daf', 'hints' }

-- mock values
local mock_address = ffi.C.kr_straddr_socket('127.0.0.1', 0)
local mock_src_address = ffi.C.kr_straddr_socket('127.0.0.2', 0)

-- helper to wait for query resolution
local function wait_resolve(qname, qtype, proto)
	local waiting, done, cond = false, false, condition.new()
	local rcode, answers, aa, tc, flags = kres.rcode.SERVFAIL, {}, false, false, {}
	resolve {
		name = qname,
		type = qtype,
		init = function (req)
			req = kres.request_t(req)
			req.qsource.dst_addr = mock_address
			req.qsource.addr = mock_src_address
			req.qsource.tcp = proto ~= 'udp'
		end,
		finish = function (answer, req)
			answer = kres.pkt_t(answer)
			aa = answer:aa()
			tc = answer:tc()
			rcode = answer:rcode()
			answers = answer:section(kres.section.ANSWER)
			local qry = req:last()
			if qry ~= nil then
				if qry.flags.NO_0X20 then flags.NO_0X20 = true end
				if qry.flags.NO_MINIMIZE then flags.NO_MINIMIZE = true end
				if qry.flags.NO_THROTTLE then flags.NO_THROTTLE = true end
				if qry.flags.SAFEMODE then flags.SAFEMODE = true end
				if qry.flags.DNSSEC_WANT then flags.DNSSEC_WANT = false end
				if qry.flags.PERMISSIVE then flags.PERMISSIVE = true end
			end
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
	return rcode, answers, aa, tc, flags
end

local function wait_flags(qname, qtype, proto)
	return select(5, wait_resolve(qname, qtype, proto))
end

-- test builtin rules
local function test_builtin_rules()
	-- rule for localhost name
	local rcode, answers, aa = wait_resolve('localhost', kres.type.A)
	same(rcode, kres.rcode.NOERROR, 'localhost returns NOERROR')
	same(#answers, 1, 'localhost returns a result')
	same(answers[1].rdata, '\127\0\0\1', 'localhost returns local address')
	same(aa, true, 'localhost returns authoritative answer')

	-- rule for reverse localhost name
	rcode, _ = wait_resolve('127.in-addr.arpa', kres.type.PTR)
	same(rcode, kres.rcode.NXDOMAIN, '127.in-addr.arpa returns NOERROR')
	rcode, answers = wait_resolve('1.0.0.127.in-addr.arpa', kres.type.PTR)
	same(rcode, kres.rcode.NOERROR, '1.0.0.127.in-addr.arpa returns NOERROR')
	same(#answers, 1, '1.0.0.127.in-addr.arpa returns a result')
	same(answers[1].rdata, '\9localhost\0', '1.0.0.127.in-addr.arpa returns localhost')

	-- test blocking of invalid names
	rcode, _ = wait_resolve('test', kres.type.A)
	same(rcode, kres.rcode.NXDOMAIN, 'test. returns NXDOMAIN')

	-- test blocking of private reverse zones
	rcode, _ = wait_resolve('0.0.0.0.in-addr.arpa.', kres.type.PTR)
	same(rcode, kres.rcode.NXDOMAIN, '0.0.0.0.in-addr.arpa. returns NXDOMAIN')
	rcode, _ = wait_resolve('0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.', kres.type.PTR)
	same(rcode, kres.rcode.NXDOMAIN, '0..0.ip6.arpa. returns NXDOMAIN')
end

local function get_filter(rule)
	local _, _, filter = daf.compile(rule)
	return filter or function () return true end
end

-- test rules parser
local function test_parser()
	local a_query = {stype = kres.type.A}
	local aaaa_query = {stype = kres.type.AAAA}
	local txt_query = {stype = kres.type.TXT}

	-- invalid rules
	nok(daf.compile('qname'), 'rejects "qname"')
	nok(daf.compile('qname '), 'rejects "qname "')
	nok(daf.compile('qname {'), 'rejects "qname {"')
	nok(daf.compile('qname {A'), 'rejects "qname {A"')
	nok(daf.compile('qname A}'), 'rejects "qname A}"')
	nok(daf.compile('qname @ {A AAAA} deny'), 'rejects "qname @ {A AAAA} deny"')
	nok(daf.compile('qname ~ {A AAAA} deny'), 'rejects "qname ~ {A AAAA} deny"')
	nok(daf.compile('qname and'), 'rejects "qname and"')
	nok(daf.compile('qname A or'), 'rejects "qname A or"')

	local filters = {
		-- test catch all
		['deny'] = {true, true, true},
		-- test explicit operator '='
		['qtype = A deny'] = {true, nil, nil},
		-- test implicit operator '='
		['qtype A deny'] = {true, nil, nil},
		-- test multiple arguments
		['qtype { A TXT } deny'] = {true, true, nil},
		['qtype {A TXT } deny'] = {true, true, nil},
		['qtype {A TXT} deny'] = {true, true, nil},
	}

	for filter, e in pairs(filters) do
		local match = get_filter(filter)
		same(e[1], match(nil, a_query), 'matches ' .. filter .. ' (A query)')
		same(e[2], match(nil, txt_query), 'matches ' .. filter .. ' (TXT query)')
		same(e[3], match(nil, aaaa_query), 'matches ' .. filter .. ' (AAAA query)')
	end
end

-- test filters running in begin phase
local function test_actions()
	local filters = {
		'qtype = A',
		'qname = localhost',
		'dst = 127.0.0.1',
		'src = 127.0.0.2',
	}

	local expect = {
		deny = {rcode = kres.rcode.NXDOMAIN, aa = true },
		drop = {rcode = kres.rcode.SERVFAIL },
		refuse = {rcode = kres.rcode.REFUSED },
		truncate = {rcode = kres.rcode.NOERROR, tc = true, proto = 'udp'},
		['reroute 127.0.0.1-192.168.1.1'] = {rcode = kres.rcode.NOERROR, aa = true, rdata = '\192\168\1\1'},
		['rewrite localhost A 192.168.1.1'] = {rcode = kres.rcode.NOERROR, aa = true, rdata = '\192\168\1\1'},
	}

	for _, filter in pairs(filters) do
		for action, e in pairs(expect) do
			local desc = daf.add(filter .. ' ' .. action)
			same(type(desc), 'table', 'created a rule ' .. filter .. ' ' .. action)
			rcode, answer, aa, tc = wait_resolve('localhost', kres.type.A, e.proto)
			same(rcode, e.rcode, ' correct rcode for ' .. action)
			same(aa, e.aa or false, ' correct AA for ' .. action)
			same(tc, e.tc or false, ' correct TC for ' .. action)
			if e.rdata then
				same(answer[1].rdata, e.rdata, ' correct RDATA for ' .. action)
			end
			daf.del(desc.rule.id)
		end
	end
end

-- test filters setting features when talking to authoritative servers
local function test_features()
	local expect = {
		-- note: the first query will be for root server which always has disabled throttling
		['-0x20']       = { NO_THROTTLE = true, NO_0X20 = true },
		['-minimize']   = { NO_THROTTLE = true, NO_MINIMIZE = true },
		['+throttle']   = { NO_THROTTLE = nil },
		['-edns']       = { NO_THROTTLE = true, SAFEMODE = true },
		['-dnssec']     = { NO_THROTTLE = true, DNSSEC_WANT = nil },
		['+permissive'] = { NO_THROTTLE = true, PERMISSIVE = true },
	}
	for features, e in pairs(expect) do
		local desc = daf.add('features -tcp ' .. features)
		-- add rule to block all outbound queries
		local block = policy.add(policy.all(policy.DROP), 'checkout')
		-- resolve the query and check flags set in the final query
		same(type(desc), 'table', 'created a rule set features ' .. features)
		local flags = wait_flags('example.com', kres.type.A)
		daf.del(desc.rule.id)
		policy.del(block.id)
		same(flags, e, 'correct flag settings for ' .. features)
	end
end

-- plan tests
local tests = {
	test_builtin_rules,
	test_parser,
	test_actions,
	test_features,
}

return tests