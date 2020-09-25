-- SPDX-License-Identifier: GPL-3.0-or-later
local function test_session_config()
	ok(net.tls_sticket_secret(),
	   'net.tls_sticket_secret() to trigger key regeneration')
	-- There is no sufficiently new stable release of GnuTLS.
	-- ok(net.tls_sticket_secret('0123456789ABCDEF0123456789ABCDEF'),
	--    'net.tls_sticket_secret with valid key')
	boom(net.tls_sticket_secret, {{}},
	     'net.tls_sticket_secret({}) is invalid')
	boom(net.tls_sticket_secret, {'0123456789ABCDEF0123456789ABCDE'},
	     'net.tls_sticket_secret with too short key')

	boom(net.tls_sticket_secret_file, {},
	     'net.tls_sticket_secret_file without filename')
	boom(net.tls_sticket_secret_file, {{}},
	     'net.tls_sticket_secret_file with non-string filename')
	boom(net.tls_sticket_secret_file, {'/tmp/a_non_existent_file_REALLY_1528898130'},
	     'net.tls_sticket_secret_file with non-existent filename')
	boom(net.tls_sticket_secret_file, {'/dev/null'},
	     'net.tls_sticket_secret_file with empty file')
end

return {
	test_session_config
}
