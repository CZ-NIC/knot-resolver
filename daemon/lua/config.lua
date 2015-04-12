-- Default configuration
cache.open(10*MB)
-- Listen on localhost
if not next(net.list()) then
	if not pcall(net.listen, '127.0.0.1') then
		error('failed to bind to localhost#53')
	end
end