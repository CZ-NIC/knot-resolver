local function test_log_groups()
	same(get_log_groups()['system'], nil, '"system" log group not logged by default')
	add_log_groups('system')
	same(get_log_groups()['system'], true, 'add "system" log group as string')
	add_log_groups('devel')
	same(get_log_groups()['devel'], true, 'add another ("devel") log group as string')
	add_log_groups({ 'cache' })
	same(get_log_groups()['cache'], true, 'add "cache" log group as table')
	add_log_groups({ 'io', 'tests' })
	same(get_log_groups()['io'], true, 'add "io" log group as table with multiple entires')
	same(get_log_groups()['tests'], true, 'add "tests" log group as table with multiple entries')
	del_log_groups('system')
	same(get_log_groups()['system'], nil, 'remove "system" log group as string')
	del_log_groups({ 'cache' })
	same(get_log_groups()['cache'], nil, 'remove "cache" log group as table')
	del_log_groups({ 'io', 'tests' })
	same(get_log_groups()['io'], nil, 'remove "io" log group as table with multiple entries')
	same(get_log_groups()['tests'], nil, 'remove "tests" log group as table with multiple entries')
	boom(add_log_groups, { 'nonexistent' }, "nonexistent group cant't be added")
	boom(del_log_groups, { 'nonexistent2' }, "nonexistent2 group can't be removed")
end

return {
	test_log_groups,
}
