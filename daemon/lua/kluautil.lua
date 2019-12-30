local kluautil = {}

-- Get length of table
function kluautil.kr_table_len(t)
	local len = 0
	for _ in pairs(t) do
		len = len + 1
	end
	return len
end

-- Fetch over HTTPS
function kluautil.kr_https_fetch(url, ca_file, file)
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

	local headers, stream, errmsg = req:go()
	if not headers then
		errmsg = errmsg or 'unknown error'
		return nil, 'HTTP client library error: ' .. errmsg
	end
	if headers:get(':status') ~= "200" then
		return nil, 'HTTP status != 200, got ' .. headers:get(':status')
	end

	local err
	err, errmsg = stream:save_body_to_file(file)
	if err == nil then
		return nil, errmsg
	end

	file:seek ("set", 0)

	return true
end

return kluautil
