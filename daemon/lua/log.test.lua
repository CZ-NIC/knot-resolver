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
	test_log_groups,
}
