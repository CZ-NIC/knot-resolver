-- setup resolver
-- policy module should be loaded by default, do not load it explicitly

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
	ok(policy.TLS_FORWARD({{'100:dead::', insecure=true},
			       {'100:dead::@443', insecure=true}
			   }), 'TLS_FORWARD with duplicate IP addresses but different ports is allowed')
	ok(policy.TLS_FORWARD({{'100:dead::', insecure=true},
			       {'100:beef::', insecure=true}
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
	ok(policy.TLS_FORWARD({{'::1', hostname='test.'}}), 'TLS_FORWARD with just hostname (use system CA store)')
	-- FIXME: WTF?
	--boom(policy.TLS_FORWARD, {{{'::1', ca_file='/tmp/ca.crt'}}}, 'TLS_FORWARD with just CA cert')
	--boom(policy.TLS_FORWARD, {{{'::1', hostname='', ca_file='/tmp/ca.crt'}}}, 'TLS_FORWARD with empty hostname + CA cert')
	--boom(policy.TLS_FORWARD, {{{'::1', hostname='test.', ca_file='/dev/a_file_which_surely_does_NOT_exist!'}}},
	--	'TLS_FORWARD with hostname + unreadable CA cert')

end

return {
	test_tls_forward
}
