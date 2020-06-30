-- SPDX-License-Identifier: GPL-3.0-or-later
modules.load('ta_update')

-- check prerequisites
local has_http = pcall(require, 'kres_modules.http') and pcall(require, 'http.request')
if not has_http then
	pass('skipping bootstrap tests because http module is not not installed')
	done()
end

local cqueues = require("cqueues")
local socket = require("cqueues.socket")

-- unload modules which are not related to this test
if ta_signal_query then
        modules.unload('ta_signal_query')
end
if priming then
        modules.unload('priming')
end
if detect_time_skew then
        modules.unload('detect_time_skew')
end

-- Self-checks on globals
assert(help() ~= nil)
assert(worker.id ~= nil)
-- Self-checks on facilities
assert(worker.stats() ~= nil)
assert(net.interfaces() ~= nil)
-- Self-checks on loaded stuff
assert(#modules.list() > 0)
-- Self-check timers
ev = event.recurrent(1 * sec, function () return 1 end)
event.cancel(ev)
ev = event.after(0, function () return 1 end)


-- do not attempt to contact outside world using DNS, operate only on cache
net.ipv4 = false
net.ipv6 = false
-- do not listen, test is driven by config code
env.KRESD_NO_LISTEN = true

-- start test webserver
local function start_webserver()
	-- srvout = io.popen('luajit webserv.lua')
	-- TODO
	os.execute('luajit webserv.lua &')
	-- assert(srvout, 'failed to start webserver')
end

local function wait_for_webserver()
	local starttime = os.time()
	local connected = false
	while not connected and os.difftime(os.time(), starttime) < 10 do
		local con = socket.connect("localhost", 8080)
		connected, msg = pcall(con.connect, con, 3)
		cqueues.sleep (0.3)
	end
	assert(connected, string.format('unable to connect to web server: %s', msg))
end

local host = 'https://localhost:8080/'
-- avoid interference with configured keyfile_default
trust_anchors.remove('.')

local function test_err_cert()
	trust_anchors.bootstrap_ca = 'x509/wrongca.pem'
	trust_anchors.bootstrap_url = host .. 'ok1.xml'
	boom(trust_anchors.add_file, {'ok1.keys'},
		'fake server certificate is detected')
end

local function test_err_xml(testname, testdesc)
	return function()
		trust_anchors.bootstrap_ca = 'x509/ca.pem'
		trust_anchors.bootstrap_url = host .. testname .. '.xml'
		boom(trust_anchors.add_file, {testname .. '.keys'}, testdesc)
	end
end

-- dumb test, right now it cannot check content of keys because
-- it does not get written until refresh fetches DNSKEY from network
-- (and bypassing network using policy bypasses also validation
-- so it does not test anything)
local function test_ok_xml(testname, testdesc)
	return function()
		trust_anchors.bootstrap_url = host .. testname .. '.xml'
		trust_anchors.remove('.')
		same(trust_anchors.add_file(testname .. '.keys'), nil, testdesc)
	end
end

return {
	start_webserver,
	wait_for_webserver,
	test_err_cert,
	test_err_xml('err_attr_extra_attr', 'bogus TA XML with an extra attribute'),
	test_err_xml('err_attr_validfrom_invalid', 'bogus TA XML with invalid validFrom value'),
	test_err_xml('err_attr_validfrom_missing', 'bogus TA XML without mandatory validFrom attribute'),
	test_err_xml('err_elem_extra', 'bogus TA XML with an extra element'),
	test_err_xml('err_elem_missing', 'bogus TA XML without mandatory element'),
	test_err_xml('err_multi_ta', 'bogus TA XML with multiple TAs'),
	test_err_xml('unsupp_nonroot', 'unsupported TA XML for non-root zone'),
	test_err_xml('unsupp_xml_v11', 'unsupported TA XML with XML v1.1'),
	test_err_xml('ok0_badtimes', 'TA XML with no valid keys'),
	test_ok_xml('ok1_expired1', 'TA XML with 1 valid and 1 expired key'),
	test_ok_xml('ok1_notyet1', 'TA XML with 1 valid and 1 not yet valid key'),
	test_ok_xml('ok1', 'TA XML with 1 valid key'),
	test_ok_xml('ok2', 'TA XML with 2 valid keys'),
}
