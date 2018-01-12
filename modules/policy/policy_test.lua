local utils = require('test_utils')

-- setup resolver
modules = { 'policy' }

-- test for default configuration
local function test_tls_forward()
	boom(policy.TLS_FORWARD, {}, 'TLS_FORWARD without arguments')
	boom(policy.TLS_FORWARD, {'1'}, 'TLS_FORWARD with non-table argument')
	-- boom(policy.TLS_FORWARD, {{}}, 'TLS_FORWARD with empty table')
	boom(policy.TLS_FORWARD, {{{bleble=''}}}, 'TLS_FORWARD with invalid parameters in table')

	boom(policy.TLS_FORWARD, {{'1'}}, 'TLS_FORWARD with invalid IP address')
	-- boom(policy.TLS_FORWARD, {{{'::1', bleble=''}}}, 'TLS_FORWARD with valid IP and invalid parameters')
	-- boom(policy.TLS_FORWARD, {{{'127.0.0.1'}}}, 'TLS_FORWARD with missing auth parameters')

	-- boom(policy.TLS_FORWARD, {{{'::1', pin=''}}}, 'TLS_FORWARD with empty pin')
	-- boom(policy.TLS_FORWARD, {{{'::1', pin='č'}}}, 'TLS_FORWARD with bad pin')
	ok(policy.TLS_FORWARD, {{{'::1', pin='ZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NQ=='}}}, 'TLS_FORWARD with base64 pin')
	ok(policy.TLS_FORWARD, {{{'::1', pin={
					'ZTNiMGM0NDI5OGZjMWMxNDlhZmJmNGM4OTk2ZmI5MjQyN2FlNDFlNDY0OWI5MzRjYTQ5NTk5MWI3ODUyYjg1NQ==',
					'MTcwYWUzMGNjZDlmYmE2MzBhZjhjZGE2ODQxZTAwYzZiNjU3OWNlYzc3NmQ0MTllNzAyZTIwYzY5YzQ4OGZmOA=='
				}}}}, 'TLS_FORWARD with table of pins')

	ok(policy.TLS_FORWARD, {{{'::1', hostname='test.', ca='/tmp/ca.crt'}}}, 'TLS_FORWARD with hostname + CA cert')
	-- boom(policy.TLS_FORWARD, {{{'::1', hostname='test.'}}}, 'TLS_FORWARD with just hostname')
	-- boom(policy.TLS_FORWARD, {{{'::1', ca='/tmp/ca.crt'}}}, 'TLS_FORWARD with just CA cert')
	-- boom(policy.TLS_FORWARD, {{{'::1', hostname='', ca='/tmp/ca.crt'}}}, 'TLS_FORWARD with invalid hostname + CA cert')
	-- boom(policy.TLS_FORWARD, {{{'::1', hostname='test.', ca='/dev/null'}}}, 'TLS_FORWARD with hostname + unreadable CA cert')
end

return {
	test_tls_forward
}
