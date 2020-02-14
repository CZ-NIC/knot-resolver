-- SPDX-License-Identifier: GPL-3.0-or-later
-- disable networking so we can get SERVFAIL immediatelly
net.ipv4 = false
net.ipv6 = false

-- test for nsid.name() interface
local function test_nsid_name()
	if nsid then
		modules.unload('nsid')
	end
	modules.load('nsid')
	same(nsid.name(), nil, 'NSID modes not provide default NSID value')
	same(nsid.name('123456'), '123456', 'NSID value can be changed')
	same(nsid.name(), '123456', 'NSID module remembers configured NSID value')
	modules.unload('nsid')
	modules.load('nsid')
	same(nsid.name(), nil, 'NSID module reload removes configured value')
end

return {
	test_nsid_name,
}
