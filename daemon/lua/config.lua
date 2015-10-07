-- Listen on localhost
if not next(net.list()) then
	if not pcall(net.listen, '127.0.0.1') then
		error('failed to bind to localhost#53')
	end
end
-- Open cache if not set/disabled
if not cache.current_size then
	cache.size = 10 * MB
end