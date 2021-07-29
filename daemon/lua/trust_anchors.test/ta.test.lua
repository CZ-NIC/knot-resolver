-- SPDX-License-Identifier: GPL-3.0-or-later

trust_anchors.remove('.')

local ffi = require('ffi')

-- count warning messages
warn_msg = {}
overriding_msg="warning: overriding previously set trust anchors for ."
warn_msg[overriding_msg] = 0
function log_warn(grp, fmt, ...) --luacheck: no unused args
	msg = string.format(fmt, ...)
	if warn_msg[msg] ~= nil then
		warn_msg[msg] = warn_msg[msg] + 1
	end
end

-- Test that adding a revoked DNSKEY is refused.
local function test_revoked_key()
	local ta_c = kres.context().trust_anchors
	same(ffi.C.kr_ta_del(ta_c, '\0'), 0, 'remove root TAs if any')
	-- same() doesn't consider nil and typed NULL pointer equal, so we work around:
	same(ffi.C.kr_ta_get(ta_c, '\0') == nil, true, 'no TA for root is used')
	local key_crypto = 'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFV'
		.. 'QUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37'
		.. 'NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAz'
		.. 'vN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7O'
		.. 'yQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0='
	boom(trust_anchors.add, { '. 3600 DNSKEY 385 3 8 ' .. key_crypto }, 'refuse revoked key')
	same(ffi.C.kr_ta_get(ta_c, '\0') == nil, true, 'no TA for root is used')
	-- Test that we don't have another problem in the key
	trust_anchors.add('. 3600 DNSKEY 257 3 8 ' .. key_crypto)
	local root_ta = ffi.C.kr_ta_get(ta_c, '\0')
	same(root_ta == nil, false, 'we got non-NULL TA RRset')
	same(root_ta.rrs.count, 1, 'the root TA set contains one RR')
end

local function test_remove()
	-- uses root key from the previous test
	assert(trust_anchors.keysets['\0'], 'root key must be there from previous test')
	local ta_c = kres.context().trust_anchors
	local root_ta = ffi.C.kr_ta_get(ta_c, '\0')
	assert(root_ta ~= nil, 'we got non-NULL TA RRset')
	assert(root_ta.rrs.count, 1, 'we have a root TA set to be deleted')

	trust_anchors.remove('.')

	same(trust_anchors.keysets['\0'], nil, 'Lua interface does not have the removed key')
	root_ta = ffi.C.kr_ta_get(ta_c, '\0')
	same(root_ta == nil, true, 'C interface does not have the removed key')
end

local function test_add_file()
	boom(trust_anchors.add_file, {'nonwriteable/root.keys', false},
	     "Managed trust anchor in non-writeable directory")

	boom(trust_anchors.add_file, {'nonexist.keys', true},
	     "Nonexist unmanaged trust anchor file")

	is(warn_msg[overriding_msg], 0, "No override warning messages at start of test")
	trust_anchors.add_file('root.keys', true)
	trust_anchors.add_file('root.keys', true)
	is(warn_msg[overriding_msg], 1, "Warning message when override trust anchors")

	is(trust_anchors.keysets['\0'][1].key_tag, 20326,
	   "Loaded KeyTag from root.keys")
end

local function test_nta()
	assert(trust_anchors.keysets['\0'], 'root key must be there from previous tests')

	trust_anchors.set_insecure({'example.com'})
	is(trust_anchors.insecure[1], 'example.com', 'Add example.com to NTA list')
	boom(trust_anchors.set_insecure, {{'.'}}, 'Got error when adding TA . to NTA list')
	is(#trust_anchors.insecure, 1, 'Check one item in NTA list')
	is(trust_anchors.insecure[1], 'example.com', 'Check previous NTA list')
end

return {
	test_revoked_key,
	test_remove,
	test_add_file,
	test_nta,
}

