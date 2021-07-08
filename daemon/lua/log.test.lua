local function test_log_group()
	same(get_log_group()['system'], nil, '"system" log group not logged by default')
	add_log_group('system')
	same(get_log_group()['system'], true, 'adding "system" log group')
	add_log_group('devel')
	same(get_log_group()['devel'], true, 'adding another ("devel") log group')
	del_log_group('system')
	same(get_log_group()['system'], nil, 'removing "system" log group')
	boom(add_log_group, { 'nonexistent' }, "nonexistent group cant't be added")
	boom(del_log_group, { 'nonexistent2' }, "nonexistent2 group can't be removed")
end

return {
	test_log_group,
}
