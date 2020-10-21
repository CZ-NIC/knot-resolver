-- SPDX-License-Identifier: GPL-3.0-or-later
-- shorten update interval
modules.load('ta_update')
ta_update.refresh_time = 0.5 * sec
ta_update.hold_down_time = 1 * sec
sleep_time = 1.5

-- prevent build-time config from interfering with the test
trust_anchors.remove('.')

-- count . IN DNSKEY queries
counter = 0
local function counter_func (state, req)
        local answer = req:ensure_answer()
        if answer == nil then return nil end
        local qry = req:current()
        if answer:qclass() == kres.class.IN
		and qry.stype == kres.type.DNSKEY
		and kres.dname2wire(qry.sname) == '\0' then
		counter = counter + 1
        end
        return state
end
policy.add(policy.all(counter_func))

local function test_ta_update_vs_trust_anchors_dependency()
	ok(ta_update, 'ta_update module is loaded by default')

	assert(counter == 0, 'test init must work')
	same(trust_anchors.add_file('root.keys'), nil, 'load managed TA for root zone')
	same(trust_anchors.keysets['\0'].managed, true, 'managed TA has managed flag')
	same(type(ta_update.tracked['\0'].event), 'number', 'adding managed TA starts tracking')
	same(counter, 0, 'TA refresh is only scheduled')
	worker.sleep(sleep_time)
	ok(counter > 0, 'TA refresh asked for TA DNSKEY after some time')

	same(ta_update.stop('\0'), nil, 'key tracking can be stopped')
	same(ta_update.tracked['\0'], nil, 'stopping removed metadata')
	same(trust_anchors.keysets['\0'].managed, false, 'now unmanaged TA does not have managed flag')
	counter = 0
	worker.sleep(sleep_time)
	same(counter, 0, 'stop() actually prevents further TA refreshes')

	ok(modules.unload('ta_update'), 'module can be unloaded')
	same(ta_update, nil, 'unloaded module is nil')

	ok(trust_anchors.remove('.'), 'managed root TA can be removed')
	same(trust_anchors.keysets['\0'], nil, 'TA removal works')
end

local function test_unloaded()
	same(ta_update, nil, 'ta_update module is nil')
	same(trust_anchors.add_file('root.keys', false), nil, 'managed TA can be added with unloaded ta_update module')
	ok(ta_update ~= nil, 'ta_update module automatically loaded')
	ok(modules.unload('ta_update'), 'ta_update module can be unloaded')
	same(ta_update, nil, 'ta_update module is nil')

	same(trust_anchors.add_file('root.keys', true), nil, 'unmanaged TA can be added with unloaded ta_update module')
	ok(ta_update ~= nil, 'ta_update module automatically loaded')

	ok(trust_anchors.remove('.'), 'unmanaged root TA can be removed')
	same(trust_anchors.keysets['\0'], nil, 'TA removal works')

end

local function test_reload()
	ok(modules.load('ta_update'), 'module can be re-loaded')
	same(trust_anchors.add_file('root.keys', false), nil, 'managed TA can be added after loading ta_update module')
	same(counter, 0, 'TA refresh is only scheduled')
	worker.sleep(sleep_time)
	ok(counter > 0, 'TA refresh asked for TA DNSKEY after some time')
end

local function test_err_inputs()
	ok(modules.load('ta_update'), 'make sure module is loaded')
	boom(ta_update.start, {'\12nonexistent'}, 'nonexistent TA cannot be tracked')
end

return {
	test_ta_update_vs_trust_anchors_dependency,
	test_unloaded,
	test_reload,
	test_err_inputs,
}
