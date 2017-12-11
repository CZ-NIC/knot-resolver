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
	-- boom(policy.TLS_FORWARD, {{{'::1', bleble=''}}}, 'TLS_FORWARD with valid IP and invalid parameters')
	boom(policy.TLS_FORWARD, {{{'127.0.0.1'}}}, 'TLS_FORWARD with missing auth parameters')

	ok(policy.TLS_FORWARD({{'127.0.0.1', insecure=true}}), 'TLS_FORWARD with no authentication')
	boom(policy.TLS_FORWARD, {{{'100:dead::', insecure=true},
				   {'100:DEAD:0::', insecure=true}
			   }}, 'TLS_FORWARD with duplicate IP addresses is not allowed')
	ok(policy.TLS_FORWARD({{'100:dead::', insecure=true},
			       {'100:dead::@443', insecure=true}
			   }), 'TLS_FORWARD with duplicate IP addresses but different ports is allowed')

	boom(policy.TLS_FORWARD, {{{'::1', pin_sha256=''}}}, 'TLS_FORWARD with empty pin_sha256')
	-- boom(policy.TLS_FORWARD, {{{'::1', pin_sha256='č'}}}, 'TLS_FORWARD with bad pin_sha256')
	ok(policy.TLS_FORWARD({
			{'::1', pin_sha256='ZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NQ=='}
		}), 'TLS_FORWARD with base64 pin_sha256')
	ok(policy.TLS_FORWARD({
		{'::1', pin_sha256={
			'ZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NQ==',
			'MTcwYWUzMGNjZDlmYmE2MzBhZjhjZGE2ODQxZTAwYzZiNjU3OWNlYzc3NmQ0MTllNzAyZTIwYzY5YzQ4OGZmOA=='
		}}}), 'TLS_FORWARD with table of pins')

	-- ok(policy.TLS_FORWARD({{'::1', hostname='test.', ca_file='/tmp/ca.crt'}}), 'TLS_FORWARD with hostname + CA cert')
	boom(policy.TLS_FORWARD, {{{'::1', hostname='test.'}}}, 'TLS_FORWARD with just hostname')
	boom(policy.TLS_FORWARD, {{{'::1', ca_file='/tmp/ca.crt'}}}, 'TLS_FORWARD with just CA cert')
	boom(policy.TLS_FORWARD, {{{'::1', hostname='', ca_file='/tmp/ca.crt'}}}, 'TLS_FORWARD with empty hostname + CA cert')
	boom(policy.TLS_FORWARD, {{{'::1', hostname='test.', ca_file='/dev/a_file_which_surely_does_NOT_exist!'}}},
		'TLS_FORWARD with hostname + unreadable CA cert')
end

return {
	test_tls_forward
}
