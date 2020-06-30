-- SPDX-License-Identifier: GPL-3.0-or-later
local cqsocket = require('cqueues.socket')
local strerror = require('cqueues.errno').strerror

local control_sock_text, control_sock_bin

local function onerr_fail(method, errno, stacklevel)
	local errmsg = string.format('socket error: method %s err %d (%s)',
					method, errno, strerror(errno))
	fail(debug.traceback(errmsg, stacklevel))
end


local function switch_to_binary_mode(sock)
	sock:write('__binary\n')
	data = sock:read(2)
	same(data, '> ', 'propably successsful switch to binary mode')
end

local function socket_fixture()
	local path = worker.cwd..'/control/'..worker.pid
	same(true, net.listen(path, nil, {kind = 'control'}), 'new control sockets were created')

	control_sock_text = cqsocket.connect({ path = path, nonblock = true })
	control_sock_text:onerror(onerr_fail)
	control_sock_text:setmode('bn', 'bn')

	control_sock_bin = cqsocket.connect({ path = path, nonblock = true })
	control_sock_bin:onerror(onerr_fail)
	control_sock_bin:setmode('bn', 'bn')
	switch_to_binary_mode(control_sock_bin)
end

local function test_text_prompt()
	data = control_sock_text:xread(2)
	same(data, '> ', 'text prompt looks like expected')
end

local function test_text_single_command()
	local expect = "this is test"
	control_sock_text:xwrite(string.format('"%s"\n', expect))
	data = control_sock_text:xread(#expect + 2, nil, 1 --[[ sec ]])
	same(data, expect .. '\n\n',
		'text mode returns output in expected format')
end

local function binary_xread_len(sock)
	data = sock:xread(4)
	local len = tonumber(data:byte(1))
	for i=2,4 do
		len = bit.bor(bit.lshift(len, 8), tonumber(data:byte(i)))
	end

	return len
end

local function test_binary_more_syscalls()
	local len

	control_sock_bin:xwrite('worker.p')
	control_sock_bin:xwrite('id\n')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')

	control_sock_bin:xwrite('worker.p')
	control_sock_bin:xwrite('id\nworker.id\n')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.id..'\n', 'binary mode returns output in expected format')

	control_sock_bin:xwrite('worker.pid')
	control_sock_bin:xwrite('\n')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')

	control_sock_bin:xwrite('worker.pid')
	control_sock_bin:xwrite('\nworker.id')
	control_sock_bin:xwrite('\n')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(control_sock_bin)
	data = control_sock_bin:xread(len, nil, 5)
	same(data, worker.id..'\n', 'binary mode returns output in expected format')
end

local tests = {
	socket_fixture,
	test_text_prompt, -- prompt after connect
	test_text_single_command,
	test_text_prompt, -- new prompt when command is finished
	test_binary_more_syscalls,
	test_text_single_command, -- command in text mode after execute commands in binary mode
	test_text_prompt, -- new prompt when command is finished
}
return tests
