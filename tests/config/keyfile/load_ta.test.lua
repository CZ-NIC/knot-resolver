-- test fixtures

-- count warning message, fail with other than allowed message
warn_msg = {}
overriding_msg="[ ta ] warning: overriding previously set trust anchors for ."
warn_msg[overriding_msg] = 0
function warn(fmt, ...)
	msg = string.format(fmt, ...)
	if warn_msg[msg] == nil then
		fail(string.format("Not allowed warn message: %s", msg))
	else
		warn_msg[msg] = warn_msg[msg] + 1
	end
end

-- tests

boom(trust_anchors.add_file, {'nonwriteable/root.keys', false},
     "Managed trust anchor in non-writeable directory")

boom(trust_anchors.add_file, {'nonexist.keys', true},
     "Nonexist unmanaged trust anchor file")

trust_anchors.add_file('../../../../tests/config/keyfile/root2.keys', true)
trust_anchors.add_file('../../../../tests/config/keyfile/root1.keys', true)
is(warn_msg[overriding_msg], 1, "Warning message when override trust anchors")

is(trust_anchors.keysets['\0'][1].key_tag, 19036,
   "Loaded KeyTag from ../../../../tests/config/keyfile/root1.keys")

local function test_loading_from_cmdline()
	is(trust_anchors.keysets['\0'][1].key_tag , 20326,
	   "Loaded KeyTag from cmdline file keyfile/root2.keys")
	is(warn_msg[overriding_msg], 2, "Warning message when override trust anchors")
end

return {test_loading_from_cmdline}
