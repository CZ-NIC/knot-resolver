#!/usr/bin/env luajit
-- SPDX-License-Identifier: GPL-3.0-or-later
cli_bin = 'kresd -q -c -'
-- Work around OS X stripping dyld variables
libdir = os.getenv('DYLD_LIBRARY_PATH')
if libdir then
	cli_bin = string.format('DYLD_LIBRARY_PATH="%s" %s', libdir, cli_bin)
end
cli_cmd = [[echo '
option("ALWAYS_CUT", true)
%s
return resolve("%s", kres.type.%s, kres.class.%s, 0,
function (pkt, req)
	local ok, err = pcall(function () %s end)
	if not ok then
		print(err)
	end
	quit()
end)']]
-- Parse CLI arguments
local function help()
	name = 'kresd-query.lua'
	print(string.format('Usage: %s [-t type] [-c class] [-C config] <name> <script>', name))
	print('Execute a single-shot query and run a script on the result.')
	print('There are two variables available: pkt (kres.pkt_t), req (kres.request_t)')
	print('See modules README to learn about their APIs.')
	print('')
	print('Options:')
	print('\t-h,--help        ... print this help')
	print('\t-t TYPE          ... query for given type (default: A)')
	print('\t-c CLASS         ... query in given class (default: IN)')
	print('\t-C config_str    ... kresd-style config (default: -)')
	print('Examples:')
	print('\t'..name..' -t SOA cz "print(pkt:qname())"         ... print response QNAME')
end
-- Parse CLI arguments
if #arg < 2 then help() return 1 end
local qtype, qclass, qname = 'A', 'IN', nil
local config, scripts = '', {}
k = 1 while k <= #arg do
	local v = arg[k]
	if v == '-h' or v == '--help' then
		return help()
	elseif v == '-C' then
		k = k + 1
		config = arg[k]
	elseif v == '-c' then
		k = k + 1
		qclass = arg[k]:upper()
	elseif v == '-t' then
		k = k + 1
		qtype = arg[k]:upper()
	elseif v:byte() == string.byte('-') then
		return help()
	elseif not qname then
		qname = v
	else
		table.insert(scripts, v)
	end
	k = k + 1
end
cli_cmd = string.format(cli_cmd, config, qname, qtype, qclass, table.concat(scripts, ' '))
return os.execute(cli_cmd..' | '..cli_bin)
