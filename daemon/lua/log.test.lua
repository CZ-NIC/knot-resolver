local function test_log_groups()
	same(log_groups(), {}, 'no groups are logged by default')
	same(log_groups({'system'}), {'system'}, 'configure "system" group')
	same(log_groups({'devel'}), {'devel'}, 'another call overrides previously set groups')
	same(log_groups({'devel', 'system'}), {'system', 'devel'}, 'configure multiple groups')
	same(log_groups({}), {}, 'clear groups with empty table')
	boom(log_groups, { 'string' }, "group argument can't be string")
	boom(log_groups, { {'nonexistent'} }, "nonexistent group can't be added")
	boom(log_groups, { 1, 2 }, "group doesn't take multiple arguments")
end

return {
	test_log_groups,
}
