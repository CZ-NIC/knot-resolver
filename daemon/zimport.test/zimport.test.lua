-- unload modules which are not related to this test
-- SPDX-License-Identifier: GPL-3.0-or-later

if ta_signal_query then
        modules.unload('ta_signal_query')
end
if priming then
        modules.unload('priming')
end
if detect_time_skew then
        modules.unload('detect_time_skew')
end

-- do not listen, test is driven by config code
env.KRESD_NO_LISTEN = true


cache.size = 5*MB
log_groups({'prefil'})

--[[ This test checks ZONEMD computation on some model cases. (no DNSSEC validation)
	https://www.rfc-editor.org/rfc/rfc8976.html#name-example-zones-with-digests
--]]


local function test_zone(file_name, success) return function()
	local import_res = require('ffi').C.zi_zone_import({
		zone_file = file_name,
		zonemd = true,
		downgrade = true,
	})
	if success == nil or success then
		is(import_res, 0, 'zone import should start OK for file ' .. file_name)
	else
		isnt(import_res, 0, 'zone import should fail for file ' .. file_name)
	end
	worker.sleep(0.2)  -- zimport is delayed by 100 ms from function call
end end

return {
	test_zone('tz-rfc-a1.zone'),
	test_zone('tz-rfc-a1-bad.zone', false),
	test_zone('tz-rfc-a2.zone'),
	test_zone('tz-rfc-a3.zone'),
	test_zone('tz-rfc-a4.zone'),
	test_zone('tz-rfc-a5.zone'),
}
