
-- Get length of table
function kr_table_len (t)
	local len = 0
	for _ in pairs(t) do
		len = len + 1
	end
	return len
end

-- Fetch over HTTPS
function kr_https_fetch (url, ca_file, file)
	local http_ok, http_request = pcall(require, 'http.request')
	local openssl_ok, openssl_ctx = pcall(require, 'openssl.ssl.context')

	if not http_ok or not openssl_ok then
		return nil, 'error: lua-http and luaossl libraries are missing (but required)'
	end

	assert(string.match(url, '^https://'))
	assert(ca_file)

	local req = http_request.new_from_uri(url)
	req.ctx = openssl_ctx.new()
	local store = req.ctx:getStore()
	store:add(ca_file)

	req.ctx:setVerify(openssl_ctx.VERIFY_PEER)
	req.tls = true

	local headers, stream = req:go()
	assert(headers, 'HTTP client library error')
	if headers:get(':status') ~= "200" then
		return nil, headers:get(':status')
	end

	local err
	err, errmsg = stream:save_body_to_file(file)
	if err == nil then
		return err, errmsg
	end

	file:seek ("set", 0)

	return true
end

