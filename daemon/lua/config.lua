-- Listen on localhost
if not next(net.list()) and not env.KRESD_NO_LISTEN then
	local ok, err = pcall(net.listen, '127.0.0.1')
	if not ok then
		error('bind to 127.0.0.1@53 '..err)
	end
	-- IPv6 loopback may fail
	ok, err = pcall(net.listen, '::1')
	if not ok and verbose() then
		print('bind to ::1@53 '..err)
	end
	-- Exit when kresd isn't listening on any interfaces
	if not next(net.list()) then
		panic('not listening on any interface, exiting...')
	end
end
-- Open cache if not set/disabled
if not cache.current_size then
	cache.size = 100 * MB
end

-- If no addresses for root servers are set, load them from the default file
if require('ffi').C.kr_zonecut_is_empty(kres.context().root_hints) then
	_hint_root_file()
end

if not trust_anchors.keysets['\0'] and trust_anchors.keyfile_default then
	if io.open(trust_anchors.keyfile_default, 'r') then
		trust_anchors.config(trust_anchors.keyfile_default, true)
	else
		panic("cannot open default trust anchor file:'%s'",
		      trust_anchors.keyfile_default
		)
	end
end
