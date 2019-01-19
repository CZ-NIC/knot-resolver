
local ffi = require('ffi')

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


return {
	test_revoked_key()
}

