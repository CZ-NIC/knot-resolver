-- SPDX-License-Identifier: GPL-3.0-or-later
-- setup resolver
-- policy module should be loaded by default, do not load it explicitly

-- do not attempt to contact outside world, operate only on cache
net.ipv4 = false
net.ipv6 = false
-- do not listen, test is driven by config code
env.KRESD_NO_LISTEN = true

-- test for default configuration
local function test_tls_forward()
	boom(policy.TLS_FORWARD, {}, 'TLS_FORWARD without arguments')
	boom(policy.TLS_FORWARD, {'1'}, 'TLS_FORWARD with non-table argument')
	boom(policy.TLS_FORWARD, {{}}, 'TLS_FORWARD with empty table')
	boom(policy.TLS_FORWARD, {{{}}}, 'TLS_FORWARD with empty target table')
	boom(policy.TLS_FORWARD, {{{bleble=''}}}, 'TLS_FORWARD with invalid parameters in table')

	boom(policy.TLS_FORWARD, {{'1'}}, 'TLS_FORWARD with invalid IP address')
	boom(policy.TLS_FORWARD, {{{'::1', bleble=''}}}, 'TLS_FORWARD with valid IP and invalid parameters')
	boom(policy.TLS_FORWARD, {{{'127.0.0.1'}}}, 'TLS_FORWARD with missing auth parameters')

	ok(policy.TLS_FORWARD({{'127.0.0.1', insecure=true}}), 'TLS_FORWARD with no authentication')
	boom(policy.TLS_FORWARD, {{{'100:dead::', insecure=true},
				   {'100:DEAD:0::', insecure=true}
			   }}, 'TLS_FORWARD with duplicate IP addresses is not allowed')
	ok(policy.TLS_FORWARD({{'100:dead::2', insecure=true},
			       {'100:dead::2@443', insecure=true}
			   }), 'TLS_FORWARD with duplicate IP addresses but different ports is allowed')
	ok(policy.TLS_FORWARD({{'100:dead::3', insecure=true},
			       {'100:beef::3', insecure=true}
			   }), 'TLS_FORWARD with different IPv6 addresses is allowed')
	ok(policy.TLS_FORWARD({{'127.0.0.1', insecure=true},
			       {'127.0.0.2', insecure=true}
		           }), 'TLS_FORWARD with different IPv4 addresses is allowed')

	boom(policy.TLS_FORWARD, {{{'::1', pin_sha256=''}}}, 'TLS_FORWARD with empty pin_sha256')
	boom(policy.TLS_FORWARD, {{{'::1', pin_sha256='č'}}}, 'TLS_FORWARD with bad pin_sha256')
	boom(policy.TLS_FORWARD, {{{'::1', pin_sha256='d161VN6aMSSdRN/TSDP6HZOHdaqcIvISlyFB9xLbGg='}}},
		'TLS_FORWARD with bad pin_sha256 (short base64)')
	boom(policy.TLS_FORWARD, {{{'::1', pin_sha256='bbd161VN6aMSSdRN/TSDP6HZOHdaqcIvISlyFB9xLbGg='}}},
		'TLS_FORWARD with bad pin_sha256 (long base64)')
	ok(policy.TLS_FORWARD({
			{'::1', pin_sha256='g1PpXsxqPchz2tH6w9kcvVXqzQ0QclhInFP2+VWOqic='}
		}), 'TLS_FORWARD with base64 pin_sha256')
	ok(policy.TLS_FORWARD({
		{'::1', pin_sha256={
			'ev1xcdU++dY9BlcX0QoKeaUftvXQvNIz/PCss1Z/3ek=',
			'SgnqTFcvYduWX7+VUnlNFT1gwSNvQdZakH7blChIRbM=',
			'bd161VN6aMSSdRN/TSDP6HZOHdaqcIvISlyFB9xLbGg=',
		}}}), 'TLS_FORWARD with a table of pins')

	-- ok(policy.TLS_FORWARD({{'::1', hostname='test.', ca_file='/tmp/ca.crt'}}), 'TLS_FORWARD with hostname + CA cert')
	ok(policy.TLS_FORWARD({{'::1', hostname='test.'}}),
		'TLS_FORWARD with just hostname (use system CA store)')
	boom(policy.TLS_FORWARD, {{{'::1', ca_file='/tmp/ca.crt'}}},
		'TLS_FORWARD with just CA cert')
	boom(policy.TLS_FORWARD, {{{'::1', hostname='', ca_file='/tmp/ca.crt'}}},
		'TLS_FORWARD with empty hostname + CA cert')
	boom(policy.TLS_FORWARD, {
			{{'::1', hostname='test.', ca_file='/dev/a_file_which_surely_does_NOT_exist!'}}
		}, 'TLS_FORWARD with hostname + unreadable CA cert')

end

local function test_slice()
	boom(policy.slice, {function() end}, 'policy.slice() without any action')
	ok(policy.slice, {function() end, policy.FORWARD, policy.FORWARD})
end

local function mirror_parser(srv, cv, nqueries)
	local ffi = require('ffi')
	local test_end = 0
	local TIMEOUT = 5  -- seconds

	while true do
		local input = srv:xread('*a', 'bn', TIMEOUT)
		if not input then
			cv:signal()
			return false, 'mirror: timeout'
		end
		--print(#input, input)
		-- convert query to knot_pkt_t
		local wire = ffi.cast("void *", input)
		local pkt = ffi.gc(ffi.C.knot_pkt_new(wire, #input, nil), ffi.C.knot_pkt_free)
		if not pkt then
			cv:signal()
			return false, 'mirror: packet allocation error'
		end

		local result = ffi.C.knot_pkt_parse(pkt, 0)
		if result ~= 0 then
			cv:signal()
			return false, 'mirror: packet parse error'
		end
		--print(pkt)
		test_end = test_end + 1

		if test_end == nqueries then
			cv:signal()
			return true, 'packet mirror pass'
		end

	end
end

local function test_mirror()
	local kluautil = require('kluautil')
	local socket = require('cqueues.socket')
	local cond = require('cqueues.condition')
	local cv = cond.new()
	local queries = {}
	local srv = socket.listen({
		host = "127.0.0.1",
		port = 36659,
		type = socket.SOCK_DGRAM,
	})
	-- binary mode, no buffering
	srv:setmode('bn', 'bn')

	queries["bla.mujtest.cz."] = kres.type.AAAA
	queries["bla.mujtest2.cz."] = kres.type.AAAA

	-- UDP server for test
	worker.bg_worker.cq:wrap(function()
		local err, msg = mirror_parser(srv, cv, kluautil.kr_table_len(queries))

		ok(err, msg)
	end)

	policy.add(policy.suffix(policy.MIRROR('127.0.0.1@36659'), policy.todnames({'mujtest.cz.'})))
	policy.add(policy.suffix(policy.MIRROR('127.0.0.1@36659'), policy.todnames({'mujtest2.cz.'})))

	for name, rtype in pairs(queries) do
		resolve(name, rtype)
	end

	cv:wait()
end

return {
	test_tls_forward,
	test_mirror,
	test_slice,
}
