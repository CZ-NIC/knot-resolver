local function test_log_level()
	same(log_level(), 'notice', 'default level is notice')
	same(verbose(), false, 'verbose is not set by default')
	same(log_level('crit'), 'crit', '"crit" level can be set')
	same(log_level('err'), 'err', '"err" level can be set')
	same(log_level('warning'), 'warning', '"warning" level can be set')
	same(log_level('notice'), 'notice', '"notice" level can be set')
	same(log_level('info'), 'info', '"info" level can be set')
	same(log_level('debug'), 'debug', '"debug" level can be set')
	same(verbose(), true, 'verbose is active when debug level is set')
	same(verbose(false), false, 'verbose can be used to turn off debug level')
	same(log_level(), 'notice', 'verbose returns log level to notice')
	boom(log_level, { 'xxx' }, "unknown level can't be used")
	boom(log_level, { 7 }, "numbered levels aren't supported")
	boom(log_level, { 1, 2 }, "level doesn't take multiple arguments")
end

local function test_log_target()
	same(log_target(), 'stderr', 'default target is stderr')
	same(log_target('stdout'), 'stdout', 'stdout target can be set')
	same(log_target('syslog'), 'syslog', 'syslog target can be set')
	same(log_target('stderr'), 'stderr', 'stderr target can be set')
	boom(log_level, { 'xxx' }, "unknown target can't be used")
	boom(log_level, { 'stderr', 'syslog' }, "target doesn't take multiple arguments")
end

local function test_log_groups()
	same(log_groups()['system'], nil, '"system" group not logged by default')
	same(log_groups({'system'})['system'], true, 'configure "system" group')
	same(log_groups({'devel'})['system'], nil, 'another call overrides previously set groups')
	same(log_groups()['devel'], true, 'use empty args to get active groups')
	same(log_groups({'devel', 'system'})['system'], true, 'configure multiple groups')
	same(log_groups()['devel'], true, 'configure multiple groups (check another group)')
	same(log_groups({ })['devel'], nil, 'clear groups with empty table')
	boom(log_groups, { 'string' }, "group argument can't be string")
	boom(log_groups, { {'nonexistent'} }, "nonexistent group can't be added")
	boom(log_groups, { 1, 2 }, "group doesn't take multiple arguments")
end

return {
	test_log_level,
	test_log_target,
	test_log_groups,
}
