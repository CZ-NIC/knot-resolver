-- setup resolver
modules = { 'version' }

-- don't wait for events
event.cancel = function () end
event.recurrent = function (_, f, ...) f(...) end

-- mock answer
local mock_data = 'stable:v1.5.0|latest:v1.5.0|CVE:1234'
local mock_answer = {
	rcode = function() return kres.rcode.NOERROR end,
	rrsets = function ()
		return {
			{tostring = function() return mock_data end}
		}
	end,
}

-- override resolve
kres.pkt_t = function () return mock_answer end
resolve = function (t)
	t.finish({})
end

-- test if current version passes silently
local function test_current_version()
	package_version = function () return '1.5.0' end
	log = boom -- fail if it logs
	version.config()
	pass('current version doesn\'t log anything')
	package_version = function () return '1.5.0-dev' end
	log = boom -- fail if it logs
	version.config()
	pass('current version + extra doesn\'t log anything')
end
-- test if it reports warning on older version
local function test_old_version()
	package_version = function () return '1.4.0' end
	local logged, warned
	log = function () logged = true end
	warn = function () warned = true end
	version.config()
	ok(logged, 'printed information about version change')
	ok(warned, 'warned about assigned CVE')
end

local function test_bad_input()
	package_version = function () return '1.4.0' end
	mock_data = 'stable:v1.5.0|latest:v1.5.0' -- CVE missing
	version.config()
	pass('missing CVE doesn\'t fail')
	mock_answer.rrsets = function () return {} end
	local logged = ''
	log = function (x) logged = x end
	version.config()
	ok(logged:find('failed'), 'catches empty response')
end

-- return test set
return {
	test_current_version,
	test_old_version,
	test_bad_input,
}