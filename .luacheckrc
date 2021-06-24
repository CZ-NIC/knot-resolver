-- SPDX-License-Identifier: GPL-3.0-or-later
std = 'luajit'
new_read_globals = {
	'cache',
	'eval_cmd',
	'event',
	'help',
	'_hint_root_file',
	'hostname',
	'map',
	'modules',
	'net',
	'package_version',
	'quit',
	'resolve',
	'ta_update',
	'fromjson',
	'todname',
	'tojson',
	'user',
	'verbose',
	'worker',
	'kluautil_list_dir',
	-- Sandbox declarations
	'kB',
	'MB',
	'GB',
	'sec',
	'second',
	'minute',
	'min',
	'hour',
	'day',
	'panic',
	'log_error',
	'log_warn',
	'log_info',
	'log_debug',
	'log_fmt',
	'log_qry',
	'log_req',
	'LOG_CRIT',
	'LOG_ERR',
	'LOG_WARNING',
	'LOG_NOTICE',
	'LOG_INFO',
	'LOG_DEBUG',
	'mode',
	'reorder_RR',
	'option',
	'env',
	'debugging',
	'kres',
	'libknot_SONAME',
	'libzscanner_SONAME',
	'table_print',
	'_ENV',
}

new_globals = {
	-- Modules are allowed to be set and accessed from global namespace
	'policy',
	'view',
	'stats',
	'http',
	'trust_anchors',
	'bogus_log',
}

-- Luacheck < 0.18 doesn't support new_read_globals
for _, v in ipairs(new_read_globals) do
	table.insert(new_globals, v)
end

exclude_files = {
	'modules/policy/lua-aho-corasick', -- Vendored
	'tests/config/tapered',
	'build*/**', -- build outputs
	'pkg/**', -- packaging outputs
}

-- Ignore some pedantic checks
ignore = {
	'4.1/err', -- Shadowing err
	'4.1/.',   -- Shadowing one letter variables
}

-- Sandbox can set global variables
files['**/daemon/lua'].ignore = {'111', '121', '122'}
files['**/daemon/lua/kres-gen-*.lua'].ignore = {'631'} -- Allow overly long lines
-- Tests and scripts can use global variables
files['scripts'].ignore = {'111', '112', '113'}
files['tests'].ignore = {'111', '112', '113'}
files['**/utils/upgrade'].ignore = {'111', '112', '113'}
files['**/modules/**/*.test.lua'].ignore = {'111', '112', '113', '121', '122'}
files['**/daemon/**/*.test.lua'].ignore = {'111', '112', '113', '121', '122'}
