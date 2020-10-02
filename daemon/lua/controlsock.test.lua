-- SPDX-License-Identifier: GPL-3.0-or-later
local cqsocket = require('cqueues.socket')
local strerror = require('cqueues.errno').strerror

-- TODO: we get memory leaks from cqueues, but CI runs this without leak detection anyway

local ctrl_sock_txt, ctrl_sock_bin, ctrl_sock_txt_longcmd, ctrl_sock_bin_longcmd
local ctrl_sock_txt_partcmd, ctrl_sock_bin_partcmd

local function onerr_fail(method, errno, stacklevel)
	local errmsg = string.format('socket error: method %s err %d (%s)',
					method, errno, strerror(errno))
	fail(debug.traceback(errmsg, stacklevel))
end


local function switch_to_binary_mode(sock)
	data = sock:read(2)
	sock:write('__binary\n')
	same(data, '> ', 'propably successsful switch to binary mode')
end

local function socket_connect(path)
	sock = cqsocket.connect({ path = path, nonblock = true })
	sock:onerror(onerr_fail)
	sock:setmode('bn', 'bn')

	return sock
end

local function socket_fixture()
	local path = worker.cwd..'/control/'..worker.pid
	same(true, net.listen(path, nil, {kind = 'control'}), 'new control sockets were created')

	ctrl_sock_txt = socket_connect(path)
	ctrl_sock_txt_longcmd = socket_connect(path)
	ctrl_sock_txt_partcmd = socket_connect(path)

	ctrl_sock_bin = socket_connect(path)
	switch_to_binary_mode(ctrl_sock_bin)
	ctrl_sock_bin_longcmd = socket_connect(path)
	switch_to_binary_mode(ctrl_sock_bin_longcmd)
	ctrl_sock_bin_partcmd = socket_connect(path)
	switch_to_binary_mode(ctrl_sock_bin_partcmd)
end

local function test_text_prompt()
	data = ctrl_sock_txt:xread(2)
	same(data, '> ', 'text prompt looks like expected')
end

local function test_text_single_command()
	local expect = "this is test"
	ctrl_sock_txt:xwrite(string.format('"%s"\n', expect))
	data = ctrl_sock_txt:xread(#expect + 2, nil, 1 --[[ sec ]])
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

	ctrl_sock_bin:xwrite('worker.p')
	worker.sleep(0.01)
	ctrl_sock_bin:xwrite('id\n')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')

	ctrl_sock_bin:xwrite('worker.p')
	worker.sleep(0.01)
	ctrl_sock_bin:xwrite('id\nworker.id\n')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.id..'\n', 'binary mode returns output in expected format')

	ctrl_sock_bin:xwrite('worker.pid')
	worker.sleep(0.01)
	ctrl_sock_bin:xwrite('\n')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')

	ctrl_sock_bin:xwrite('worker.pid')
	worker.sleep(0.01)
	ctrl_sock_bin:xwrite('\nworker.id')
	worker.sleep(0.01)
	ctrl_sock_bin:xwrite('\n')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.id..'\n', 'binary mode returns output in expected format')

	ctrl_sock_bin:xwrite('worker.pid\nworker.pid\nworker.pid\nworker.pid\n')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
	len = binary_xread_len(ctrl_sock_bin)
	data = ctrl_sock_bin:xread(len, nil, 5)
	same(data, worker.pid..'\n', 'binary mode returns output in expected format')
end

local function test_close_uncomplete_cmd()
	ctrl_sock_txt_partcmd:xwrite('worker.p')
	ctrl_sock_txt_partcmd:close()
	pass('close text socket with uncomplete command')

	ctrl_sock_bin_partcmd:xwrite('worker.p')
	ctrl_sock_bin_partcmd:close()
	pass('close binary socket with long uncomplete command')
end


local function test_close_during_transfer()
	ctrl_sock_txt_longcmd:xwrite(string.rep('a', 1024*1024*10))
	ctrl_sock_txt_longcmd:close()
	pass('close text socket with long uncomplete command')

	ctrl_sock_bin_longcmd:xwrite(string.rep('a', 1024*1024*10))
	ctrl_sock_bin_longcmd:close()
	pass('close binary socket with long uncomplete command')
end

local tests = {
	socket_fixture,
	test_text_prompt, -- prompt after connect
	test_text_single_command,
	test_text_prompt, -- new prompt when command is finished
	test_close_uncomplete_cmd,
	test_close_during_transfer,
	test_binary_more_syscalls,
	test_text_single_command, -- command in text mode after execute commands in binary mode
	test_text_prompt, -- new prompt when command is finished
}
return tests
