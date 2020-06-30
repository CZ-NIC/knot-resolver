-- SPDX-License-Identifier: GPL-3.0-or-later
local cqsocket = require('cqueues.socket')
local strerror = require('cqueues.errno').strerror

local control_sock

local function find_control_socket(endpoints)
	for id, endpoint in pairs(endpoints) do
		if endpoint.kind == 'control'
			and endpoint.transport.family == 'unix' then
			return endpoint.transport.path
		end
	end
	error('control socket path not found in net.list()')
end

local function onerr_fail(sock, method, errno, stacklevel)
	local errmsg = string.format('socket error: method %s err %d (%s)',
					method, errno, strerror(errno))
	fail(debug.traceback(errmsg, stacklevel))
end

local onerr_eagain
local function socket_fixture()
	local path = worker.cwd..'/control/'..worker.pid
	same(true, net.listen(path, nil, {kind = 'control'}), 'new control socket was created')
	s = cqsocket.connect({ path = path, nonblock = true })
	onerr_eagain = s:onerror(onerr_fail)
	s:setmode('bn', 'bn')
	control_sock = s
end

local function test_text_prompt()
	data = s:xread(2)
	same(data, '> ', 'text prompt looks like expected')
	--s:onerror(onerr_eagain)
	--data = s:xread(1, nil, 0)
	--s:onerror(onerr_fail)
	--same(data, nil, 'text prompt has only two bytes')
end

local function test_text_single_command()
	local expect = "this is test"
	s:xwrite(string.format('"%s"\n', expect))
	data = s:xread(#expect + 2, nil, 1 --[[ sec ]])
	same(data, expect .. '\n\n',
		'text mode returns output in expected format')
	log('DATA=%q',data) -- FIXME
end

local tests = {
	socket_fixture,
	test_text_prompt, -- prompt after connect
	test_text_single_command,
	test_text_prompt, -- new prompt when command is finished
}
return tests
