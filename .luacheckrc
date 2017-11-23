std = 'luajit'
new_read_globals = {
	'help',
	'quit',
	'hostname',
	'moduledir',
	'user',
	'verbose',
	'resolve',
	'tojson',
	'todname',
	'map',
	'net',
	'cache',
	'modules',
	'trust_anchors',
	'worker',
	'event',
	'_hint_root_file',
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
	'warn',
	'log',
	'mode',
	'trust_anchors',
	'reorder_RR',
	'option',
	'env',
	'kres',
	'trustanchor',
	'libknot_SONAME',
	'libzscanner_SONAME',
	'table_print',
	'__engine',
	'_ENV',
	'_SANDBOX',
}

new_globals = {
	-- Modules are allowed to be set and accessed from global namespace
	'policy',
	'view',
	'stats',
	'http',
}

-- Luacheck < 0.18 doesn't support new_read_globals
for _, v in ipairs(new_read_globals) do
	table.insert(new_globals, v)
end

-- Ignore test files
exclude_files = {
	'modules/policy/lua-aho-corasick', -- Vendored
}

-- Ignore some pedantic checks
ignore = {
	'4.1/err', -- Shadowing err
	'4.1/.',   -- Shadowing one letter variables
}

-- Sandbox can set global variables
files['daemon/lua'].ignore = {'111', '121', '122'}
files['daemon/lua/kres-gen.lua'].ignore = {'631'} -- Allow overly long lines
-- Tests and scripts can use global variables
files['scripts'].ignore = {'111', '112', '113'}
files['tests'].ignore = {'111', '112', '113'}
files['tests/config/test_utils.lua'].ignore = {'121'}