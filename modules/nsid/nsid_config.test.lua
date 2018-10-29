-- setup resolver
modules.load('nsid')

-- test for default configuration
local function test_nsid_config()
	boom(nsid.config, {}, 'NSID requires config table')
	boom(nsid.config, {'name'}, 'NSID requires a name')
	ok(policy.TLS_FORWARD({{'::1', hostname='test.'}}), 'TLS_FORWARD with just hostname (use system CA store)')
end

return {
	test_nsid_config
}
