-- Listen on localhost
if not next(net.list()) then
	local ok, err = pcall(net.listen, {'127.0.0.1', '::1'})
	if not ok then
		error('bind to localhost#53 '..err)
	end
end
-- Open cache if not set/disabled
if not cache.current_size then
	cache.size = 100 * MB
end