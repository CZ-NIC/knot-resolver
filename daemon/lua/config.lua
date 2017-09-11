-- Listen on localhost
if not next(net.list()) then
	local ok, err = pcall(net.listen, '127.0.0.1')
	if not ok then
		error('bind to 127.0.0.1@53 '..err)
	end
	-- IPv6 loopback may fail
	ok, err = pcall(net.listen, '::1')
	if not ok and verbose() then
		print('bind to ::1@53 '..err)
	end
end
-- Open cache if not set/disabled
if not cache.current_size then
	cache.size = 100 * MB
end

if kres.context().root_hints.nsset.root == nil then
	_hint_root_file()
end
