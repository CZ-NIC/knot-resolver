local function test_freebind()
	boom(net.listen, {'192.0.2.1', 50049},
		'net.listen() without freebind should fail')
	ok(net.listen('192.0.2.1', 50049, { freebind=true }),
		'net.listen() with freebind succeeds')
end

return {
	test_freebind,
}
